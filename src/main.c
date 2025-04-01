#include "main.h"
#include <stdio.h>
#include "mfrc522.h" // Include MFRC522 header

void LED_Init();
void UART1_Init();
void SPI2_Init();
void BUTTON_Init(); // New function declaration
unsigned char WriteTestDataToCard(unsigned char *serial);

// Define button pin
#define BUTTON_PIN GPIO_PIN_10
#define BUTTON_GPIO_PORT GPIOD
#define BUTTON_GPIO_CLK_ENABLE() __HAL_RCC_GPIOD_CLK_ENABLE()

UART_HandleTypeDef huart1;
SPI_HandleTypeDef hspi2; // SPI2 handle

// Default key for Mifare cards
static const uint8_t DefaultKey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Test data to write to the card
static const uint8_t TestData[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

// Manufacturer data to write
static const uint8_t ManufacturerData[16] = {
    0x0E, 0xA7, 0xF1, 0x29, 0x71, 0x28, 0x04, 0x00,
    0x90, 0x10, 0x15, 0x01, 0x00, 0x00, 0x00, 0x00};

// Flag to control whether to attempt writing to manufacturer block
static uint8_t attemptManufacturerWrite = 0;

unsigned char WriteManufacturerData(unsigned char *serial)
{
    unsigned char status;
    unsigned char read_data[16];
    unsigned int i;
    unsigned char data_match = 1;

    printf("\r\n--- WRITING MANUFACTURER DATA ---\r\n");

    // Authenticate sector 0
    status = PcdAuthState(PICC_AUTHENT1A, 0, (unsigned char *)DefaultKey, serial);
    if (status != MI_OK)
    {
        printf("Authentication failed for manufacturer data block\r\n");
        return status;
    }

    // Write manufacturer data to block 0
    printf("Writing manufacturer data: ");
    for (i = 0; i < 16; i++)
    {
        printf("%02X", ManufacturerData[i]);
    }
    printf("\r\n");

    status = PcdWrite(0, (unsigned char *)ManufacturerData);
    if (status != MI_OK)
    {
        printf("Failed to write manufacturer data\r\n");
        return status;
    }

    printf("Manufacturer data written successfully\r\n");

    // Read back the data to verify
    status = PcdRead(0, read_data);
    if (status != MI_OK)
    {
        printf("Failed to read back manufacturer data\r\n");
        return status;
    }

    // Verify the data matches
    printf("Read back manufacturer data: ");
    for (i = 0; i < 16; i++)
    {
        printf("%02X", read_data[i]);
        if (read_data[i] != ManufacturerData[i])
        {
            data_match = 0;
        }
    }
    printf("\r\n");

    if (data_match)
    {
        printf("VERIFICATION SUCCESSFUL: Written data matches read data\r\n");
    }
    else
    {
        printf("VERIFICATION FAILED: Written data does not match read data\r\n");
    }

    return status;
}

void ReadRFIDCard(void)
{
    unsigned char status;
    unsigned char card_type[2];
    unsigned char card_serial[4];
    unsigned char card_data[16];
    unsigned int i;
    uint8_t sector, block, block_addr;

    // Request card
    status = PcdRequest(PICC_REQALL, card_type);
    if (status != MI_OK)
    {
        return;
    }

    // Print card type
    printf("\r\n===============================\r\n");
    printf("Card Type: %02X%02X\r\n", card_type[0], card_type[1]);

    // Anti-collision
    status = PcdAnticoll(card_serial);
    if (status != MI_OK)
    {
        return;
    }

    // Print card serial number
    printf("Card Serial: ");
    for (i = 0; i < 4; i++)
    {
        printf("%02X", card_serial[i]);
    }
    printf("\r\n");

    // Select card
    status = PcdSelect(card_serial);
    if (status != MI_OK)
    {
        return;
    }

    // Only write manufacturer data if flag is set
    if (attemptManufacturerWrite)
    {
        WriteManufacturerData(card_serial);
        // Reset the flag after attempting a write
        attemptManufacturerWrite = 0;

        // Reset the card after writing to manufacturer block to ensure fresh state
        printf("Resetting RFID reader and card after manufacturer block write...\r\n");
        PcdHalt();
        PcdReset();
        PcdAntennaOff();
        HAL_Delay(100);
        PcdAntennaOn();
        HAL_Delay(100);
        printf("Reset complete. Please remove card and present it again.\r\n");
        HAL_Delay(2000);
        return;
    }

    printf("\r\n--- READING ALL CARD DATA ---\r\n");
    // Read all sectors (typically 1 sectors in a standard MIFARE 1K card)
    for (sector = 0; sector < 1; sector++)
    {
        // Authenticate each sector
        // First block of the sector is: sector * 4
        block_addr = sector * 4;

        // Authenticate using PICC_AUTHENT1A with the default key
        status = PcdAuthState(PICC_AUTHENT1A, block_addr, (unsigned char *)DefaultKey, card_serial);
        if (status != MI_OK)
        {
            printf("Authentication failed for sector %d\r\n", sector);

            // Try alternative keys if default key fails
            // This can help if the card's auth structure was changed
            static const uint8_t AlternativeKey[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
            static const uint8_t FactoryKey[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            printf("Trying alternative key for sector %d...\r\n", sector);
            status = PcdAuthState(PICC_AUTHENT1A, block_addr, (unsigned char *)AlternativeKey, card_serial);
            if (status != MI_OK)
            {
                printf("Alternative key failed, trying factory key...\r\n");
                status = PcdAuthState(PICC_AUTHENT1A, block_addr, (unsigned char *)FactoryKey, card_serial);
                if (status != MI_OK)
                {
                    printf("All keys failed for sector %d\r\n", sector);
                    continue; // Skip to next sector
                }
            }
        }

        // Read each block in the sector (4 blocks per sector)
        for (block = 0; block < 4; block++)
        {
            // Calculate block address
            block_addr = sector * 4 + block;

            // Special notes for important blocks but don't skip them
            if (sector == 0 && block == 0)
            {
                printf("Sector %d, Block %d (Manufacturer data): ", sector, block);
            }
            else if (block == 3)
            {
                printf("Sector %d, Block %d (Sector trailer): ", sector, block);
            }
            else
            {
                printf("Sector %d, Block %d: ", sector, block);
            }

            // Read block data
            status = PcdRead(block_addr, card_data);
            if (status != MI_OK)
            {
                printf("Read failed\r\n");
                continue;
            }

            // Display block data
            for (i = 0; i < 16; i++)
            {
                printf("%02X", card_data[i]);
            }
            printf("\r\n");
        }
    }

    // Halt card
    PcdHalt();

    // Blink LED to indicate successful read
    HAL_GPIO_WritePin(LED_GPIO_PORT, LED_PIN, GPIO_PIN_SET);
    HAL_Delay(100);
    HAL_GPIO_WritePin(LED_GPIO_PORT, LED_PIN, GPIO_PIN_RESET);
    HAL_Delay(100);
    HAL_GPIO_WritePin(LED_GPIO_PORT, LED_PIN, GPIO_PIN_SET);
    HAL_Delay(100);
    HAL_GPIO_WritePin(LED_GPIO_PORT, LED_PIN, GPIO_PIN_RESET);

    // Add delay to avoid multiple reads of the same card
    HAL_Delay(1000); // Extended delay after reading all blocks
}

int main(void)
{
    HAL_Init();
    LED_Init();
    UART1_Init();
    SPI2_Init();   // Initialize SPI2 for MFRC522
    BUTTON_Init(); // Initialize PD10 as button input

    printf("UART1 and SPI2 Initialized - RFID Reader Starting\r\n");
    printf("Press PD10 button to attempt manufacturer data write\r\n");
    printf("WARNING: Writing to manufacturer block may damage some cards!\r\n");

    // Initialize MFRC522
    PcdReset();
    PcdAntennaOff();
    PcdAntennaOn();
    printf("MFRC522 Initialized\r\n");

    while (1)
    {
        // Check if button is pressed to set manufacturer write flag
        if (HAL_GPIO_ReadPin(BUTTON_GPIO_PORT, BUTTON_PIN) == GPIO_PIN_RESET)
        {
            attemptManufacturerWrite = 1;
            printf("Manufacturer write mode activated for next card!\r\n");
            HAL_Delay(1000); // Debounce
        }

        // Try to read RFID card
        ReadRFIDCard();

        // Small delay between scans
        HAL_Delay(200);
    }
}

void LED_Init()
{
    LED_GPIO_CLK_ENABLE();
    GPIO_InitTypeDef GPIO_InitStruct;
    GPIO_InitStruct.Pin = LED_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_PULLDOWN;
    GPIO_InitStruct.Speed = GPIO_SPEED_HIGH;
    HAL_GPIO_Init(LED_GPIO_PORT, &GPIO_InitStruct);
}

void UART1_Init()
{
    UART1_GPIO_CLK_ENABLE();
    UART1_CLK_ENABLE();

    GPIO_InitTypeDef GPIO_InitStruct = {0};

    // Configure UART1 TX pin
    GPIO_InitStruct.Pin = UART1_TX_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART1;
    HAL_GPIO_Init(UART1_GPIO_PORT, &GPIO_InitStruct);

    // Configure UART1 RX pin
    GPIO_InitStruct.Pin = UART1_RX_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    HAL_GPIO_Init(UART1_GPIO_PORT, &GPIO_InitStruct);

    // Configure UART1
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 115200;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart1);
}

// Redirect printf to UART1
int _write(int file, char *ptr, int len)
{
    HAL_UART_Transmit(&huart1, (uint8_t *)ptr, len, HAL_MAX_DELAY);
    return len;
}

void SysTick_Handler(void)
{
    HAL_IncTick();
}

void SPI2_Init()
{
    // Enable clock for GPIOB
    SPI2_GPIO_CLK_ENABLE();

    // Enable clock for SPI2 peripheral
    SPI2_CLK_ENABLE();

    // Configure GPIO pins for SPI2
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    // Configure SCK, MISO, MOSI pins
    GPIO_InitStruct.Pin = SPI2_SCK_PIN | SPI2_MISO_PIN | SPI2_MOSI_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF5_SPI2; // Set to the alternate function for SPI2
    HAL_GPIO_Init(SPI2_GPIO_PORT, &GPIO_InitStruct);

    // Configure CS pin as output
    GPIO_InitStruct.Pin = SPI2_CS_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(SPI2_GPIO_PORT, &GPIO_InitStruct);

    // Set CS pin high (inactive)
    HAL_GPIO_WritePin(SPI2_GPIO_PORT, SPI2_CS_PIN, GPIO_PIN_SET);

    // Configure RST pin as output
    GPIO_InitStruct.Pin = MFRC522_RST_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(SPI2_GPIO_PORT, &GPIO_InitStruct);

    // Configure SPI2
    hspi2.Instance = SPI2;
    hspi2.Init.Mode = SPI_MODE_MASTER;
    hspi2.Init.Direction = SPI_DIRECTION_2LINES;
    hspi2.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi2.Init.CLKPolarity = SPI_POLARITY_LOW;
    hspi2.Init.CLKPhase = SPI_PHASE_1EDGE;
    hspi2.Init.NSS = SPI_NSS_SOFT;
    hspi2.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16; // Adjust based on your clock speed
    hspi2.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi2.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi2.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    hspi2.Init.CRCPolynomial = 7;

    HAL_SPI_Init(&hspi2);

    // A small delay after initialization
    HAL_Delay(10);
}

void BUTTON_Init()
{
    // Enable clock for GPIOD
    BUTTON_GPIO_CLK_ENABLE();

    GPIO_InitTypeDef GPIO_InitStruct;
    GPIO_InitStruct.Pin = BUTTON_PIN;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(BUTTON_GPIO_PORT, &GPIO_InitStruct);
}