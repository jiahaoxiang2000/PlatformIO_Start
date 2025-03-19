#ifndef MAIN_H
#define MAIN_H

#include "stm32l4xx_hal.h"

#define LED_PIN GPIO_PIN_7
#define LED_GPIO_PORT GPIOE
#define LED_GPIO_CLK_ENABLE() __HAL_RCC_GPIOE_CLK_ENABLE()

// UART1 definitions
#define UART1_TX_PIN GPIO_PIN_9
#define UART1_RX_PIN GPIO_PIN_10
#define UART1_GPIO_PORT GPIOA
#define UART1_GPIO_CLK_ENABLE() __HAL_RCC_GPIOA_CLK_ENABLE()
#define UART1_CLK_ENABLE() __HAL_RCC_USART1_CLK_ENABLE()

extern UART_HandleTypeDef huart1;

#endif // MAIN_H