char PcdReset(void);
void PcdAntennaOn(void);
void PcdAntennaOff(void);
char PcdRequest(unsigned char req_code, unsigned char *pTagType);
char PcdAnticoll(unsigned char *pSnr);
char PcdSelect(unsigned char *pSnr);
char PcdAuthState(unsigned char auth_mode, unsigned char addr, unsigned char *pKey, unsigned char *pSnr);
char PcdRead(unsigned char addr, unsigned char *pData);
char PcdWrite(unsigned char addr, unsigned char *pData);
char PcdValue(unsigned char dd_mode, unsigned char addr, unsigned char *pValue);
char PcdBakValue(unsigned char sourceaddr, unsigned char goaladdr);
char PcdHalt(void);
char PcdComMF522(unsigned char Command,
                 unsigned char *pInData,
                 unsigned char InLenByte,
                 unsigned char *pOutData,
                 unsigned int *pOutLenBit);
void CalulateCRC(unsigned char *pIndata, unsigned char len, unsigned char *pOutData);
void WriteRawRC(unsigned char Address, unsigned char value);
unsigned char ReadRawRC(unsigned char Address);
void SetBitMask(unsigned char reg, unsigned char mask);
void ClearBitMask(unsigned char reg, unsigned char mask);

/////////////////////////////////////////////////////////////////////
// MF522 Command codes
/////////////////////////////////////////////////////////////////////
#define PCD_IDLE 0x00       // Cancel the current command
#define PCD_AUTHENT 0x0E    // Authentication key
#define PCD_RECEIVE 0x08    // Receive data
#define PCD_TRANSMIT 0x04   // Send data
#define PCD_TRANSCEIVE 0x0C // Send and receive data
#define PCD_RESETPHASE 0x0F // Reset
#define PCD_CALCCRC 0x03    // CRC calculation

/////////////////////////////////////////////////////////////////////
// Mifare_One card command codes
/////////////////////////////////////////////////////////////////////
#define PICC_REQIDL 0x26    // Search for cards that are not in HALT state
#define PICC_REQALL 0x52    // Search for all cards
#define PICC_ANTICOLL1 0x93 // Anti-collision
#define PICC_ANTICOLL2 0x95 // Anti-collision
#define PICC_AUTHENT1A 0x60 // Authenticate A key
#define PICC_AUTHENT1B 0x61 // Authenticate B key
#define PICC_READ 0x30      // Read
#define PICC_WRITE 0xA0     // Write
#define PICC_DECREMENT 0xC0 // Debit
#define PICC_INCREMENT 0xC1 // Charge/Credit
#define PICC_RESTORE 0xC2   // Transfer data to buffer
#define PICC_TRANSFER 0xB0  // Save buffer data to card
#define PICC_HALT 0x50      // Sleep

/////////////////////////////////////////////////////////////////////
// MF522 FIFO length definition
/////////////////////////////////////////////////////////////////////
#define DEF_FIFO_LENGTH 64 // FIFO size=64byte

/////////////////////////////////////////////////////////////////////
// MF522 Register definitions
/////////////////////////////////////////////////////////////////////
// PAGE 0
#define RFU00 0x00
#define CommandReg 0x01
#define ComIEnReg 0x02
#define DivlEnReg 0x03
#define ComIrqReg 0x04
#define DivIrqReg 0x05
#define ErrorReg 0x06
#define Status1Reg 0x07
#define Status2Reg 0x08
#define FIFODataReg 0x09
#define FIFOLevelReg 0x0A
#define WaterLevelReg 0x0B
#define ControlReg 0x0C
#define BitFramingReg 0x0D
#define CollReg 0x0E
#define RFU0F 0x0F
// PAGE 1
#define RFU10 0x10
#define ModeReg 0x11
#define TxModeReg 0x12
#define RxModeReg 0x13
#define TxControlReg 0x14
#define TxAutoReg 0x15
#define TxSelReg 0x16
#define RxSelReg 0x17
#define RxThresholdReg 0x18
#define DemodReg 0x19
#define RFU1A 0x1A
#define RFU1B 0x1B
#define MifareReg 0x1C
#define RFU1D 0x1D
#define RFU1E 0x1E
#define SerialSpeedReg 0x1F
// PAGE 2
#define RFU20 0x20
#define CRCResultRegM 0x21
#define CRCResultRegL 0x22
#define RFU23 0x23
#define ModWidthReg 0x24
#define RFU25 0x25
#define RFCfgReg 0x26
#define GsNReg 0x27
#define CWGsCfgReg 0x28
#define ModGsCfgReg 0x29
#define TModeReg 0x2A
#define TPrescalerReg 0x2B
#define TReloadRegH 0x2C
#define TReloadRegL 0x2D
#define TCounterValueRegH 0x2E
#define TCounterValueRegL 0x2F
// PAGE 3
#define RFU30 0x30
#define TestSel1Reg 0x31
#define TestSel2Reg 0x32
#define TestPinEnReg 0x33
#define TestPinValueReg 0x34
#define TestBusReg 0x35
#define AutoTestReg 0x36
#define VersionReg 0x37
#define AnalogTestReg 0x38
#define TestDAC1Reg 0x39
#define TestDAC2Reg 0x3A
#define TestADCReg 0x3B
#define RFU3C 0x3C
#define RFU3D 0x3D
#define RFU3E 0x3E
#define RFU3F 0x3F

/////////////////////////////////////////////////////////////////////
// Status codes returned during MF522 communication
/////////////////////////////////////////////////////////////////////
#define MI_OK 0
#define MI_NOTAGERR (-1)
#define MI_ERR (-2)

// the detail point of the MF522
// MF522_RST: PB9
// MF522_SCK: PB13
// MF522_NSS: PB8
// MF522_SI: PB15
// MF522_SO: PB14
