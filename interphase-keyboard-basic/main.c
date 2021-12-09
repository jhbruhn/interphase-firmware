#define INVERT
//#define COMPILE_RIGHT
#define COMPILE_LEFT

#include <stdbool.h>

#include <string.h>



#include "interphase.h"

#include "mitosis-crypto.h"

#include "nrf_delay.h"

#include "nrf_drv_adc.h"

#include "nrf_drv_clock.h"

#include "nrf_drv_config.h"

#include "nrf_drv_rtc.h"

#include "nrf_gpio.h"

#include "nrf_gzll.h"



/*****************************************************************************/
/** Configuration */
/*****************************************************************************/

const nrf_drv_rtc_t rtc_maint = NRF_DRV_RTC_INSTANCE(
    0); /**< Declaring an instance of nrf_drv_rtc for RTC0. */
const nrf_drv_rtc_t rtc_deb = NRF_DRV_RTC_INSTANCE(
    1); /**< Declaring an instance of nrf_drv_rtc for RTC1. */

// Define payload length
// TODO: DO we have to worry about this size???
#define TX_PAYLOAD_LENGTH \
  sizeof(mitosis_crypto_data_payload_t)  // ROWS ///< 5 byte payload length when
                                         // transmitting

// Data and acknowledgement payloads
static mitosis_crypto_data_payload_t
    data_payload;  ///< Payload to send to Host.
static mitosis_crypto_seed_payload_t
    ack_payload;  ///< Payloads received in ACKs from Host.

// Crypto state
static mitosis_crypto_context_t crypto;
static mitosis_crypto_context_t receiver_crypto;
static volatile bool encrypting = false;

// Debounce time (dependent on tick frequency)
#define DEBOUNCE 5
#define ACTIVITY 500

// Debug helper variables
static uint16_t max_rtx = 0;
static uint32_t rtx_count = 0;
static uint32_t tx_count = 0;
static uint32_t tx_fail = 0;
static volatile uint32_t encrypt_collisions = 0;
static volatile uint32_t encrypt_failure = 0;
static volatile uint32_t cmac_failure = 0;
static volatile uint32_t rekey_cmac_success = 0;
static volatile uint32_t rekey_cmac_failure = 0;
static volatile uint32_t rekey_decrypt_failure = 0;

// Key buffers
static uint8_t keys[ROWS], keys_snapshot[ROWS], keys_buffer[ROWS];
static uint32_t debounce_ticks, activity_ticks;
static volatile bool debouncing = false;

// Debug helper variables
static volatile bool init_ok, enable_ok, push_ok, pop_ok, tx_success;



static nrf_drv_adc_channel_t m_channel_bat =

    NRF_DRV_ADC_DEFAULT_CHANNEL(NRF_ADC_CONFIG_INPUT_2);



// Setup switch pins with pullups
static void gpio_config(void) {
  nrf_gpio_cfg_sense_input(C01, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C02, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C03, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C04, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C05, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C06, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);
  nrf_gpio_cfg_sense_input(C07, NRF_GPIO_PIN_PULLDOWN, NRF_GPIO_PIN_SENSE_HIGH);

  nrf_gpio_cfg_output(R01);
  nrf_gpio_cfg_output(R02);
  nrf_gpio_cfg_output(R03);
  nrf_gpio_cfg_output(R04);
  nrf_gpio_cfg_output(R05);
}

static void adc_config(void) {
  ret_code_t ret_code;
  // Initialize ADC
  nrf_drv_adc_config_t config = NRF_DRV_ADC_DEFAULT_CONFIG;

  nrf_drv_adc_init(&config, 0);
  // APP_ERROR_CHECK(ret_code);
  //  Configure and enable ADC channel 0

  m_channel_bat.config.config.input =
      NRF_ADC_CONFIG_SCALING_INPUT_ONE_THIRD;  // 3 * 1.2 is the scale here, at



  nrf_drv_adc_channel_enable(&m_channel_bat);
}

static void power_off(void) {
  NRF_POWER->RAMON = POWER_RAMON_ONRAM0_RAM0On << POWER_RAMON_ONRAM0_Pos |

                     POWER_RAMON_ONRAM1_RAM1On << POWER_RAMON_ONRAM1_Pos |

                     POWER_RAMON_OFFRAM0_RAM0Off << POWER_RAMON_OFFRAM0_Pos |

                     POWER_RAMON_OFFRAM1_RAM1Off << POWER_RAMON_OFFRAM1_Pos;

  NRF_POWER->RAMONB = POWER_RAMONB_ONRAM2_RAM2Off << POWER_RAMONB_ONRAM2_Pos |

                      POWER_RAMONB_ONRAM3_RAM3Off << POWER_RAMONB_ONRAM3_Pos |

                      POWER_RAMONB_OFFRAM2_RAM2Off << POWER_RAMONB_OFFRAM2_Pos |

                      POWER_RAMONB_OFFRAM3_RAM3Off << POWER_RAMONB_OFFRAM3_Pos;

  NRF_POWER->SYSTEMOFF = 1;
}

static void check_power(void) {
  nrf_adc_value_t value = 0;
  nrf_drv_adc_sample_convert(&m_channel_bat, &value);
  if (value < 280) {  // (1024 / 3.6) is the maximum, we want to stop at 1V,

                      // thus this i guess
    power_off();
  }
}

// Return the key states of one row
static uint8_t read_row(uint32_t row) {
  uint8_t buff = 0;
  uint32_t input = 0;
  nrf_gpio_pin_set(row);
  input = NRF_GPIO->IN;
  buff = (buff << 1) | ((input >> C01) & 1);
  buff = (buff << 1) | ((input >> C02) & 1);
  buff = (buff << 1) | ((input >> C03) & 1);
  buff = (buff << 1) | ((input >> C04) & 1);
  buff = (buff << 1) | ((input >> C05) & 1);
  buff = (buff << 1) | ((input >> C06) & 1);
  buff = (buff << 1) | ((input >> C07) & 1);
  buff = (buff << 1);
  nrf_gpio_pin_clear(row);
  return buff;
}

// Return the key states
static void read_keys(void) {
  keys_buffer[0] = read_row(R01);
  keys_buffer[1] = read_row(R02);
  keys_buffer[2] = read_row(R03);
  keys_buffer[3] = read_row(R04);
  keys_buffer[4] = read_row(R05);
  return;
}

static bool compare_keys(uint8_t* first, uint8_t* second, uint32_t size) {
  for (int i = 0; i < size; i++) {
    if (first[i] != second[i]) {
      return false;
    }
  }
  return true;
}

static bool empty_keys(void) {
  for (int i = 0; i < ROWS; i++) {
    if (keys_buffer[i]) {
      return false;
    }
  }
  return true;
}

// Assemble packet and send to receiver
static void send_data(void) {
  if (!encrypting) {
    encrypting = true;
    uint8_t* data = data_payload.data;
    for (int i = 0; i < ROWS; i++) {
      data[i] = keys[i];
    }
    if (mitosis_aes_ctr_encrypt(&crypto.encrypt, sizeof(data_payload.data),
                                data_payload.data, data_payload.data)) {
      // Copy the used counter and increment at the same time.
      data_payload.counter = crypto.encrypt.ctr.iv.counter++;
      // compute cmac on data and counter.
      if (mitosis_cmac_compute(&crypto.cmac, data_payload.payload,
                               sizeof(data_payload.payload),
                               data_payload.mac)) {
        if (nrf_gzll_add_packet_to_tx_fifo(PIPE_NUMBER, (uint8_t*)&data_payload,
                                           TX_PAYLOAD_LENGTH)) {
          ++tx_count;
        } else {
          ++tx_fail;
        }
      } else {
        ++cmac_failure;
      }
    } else {
      ++encrypt_failure;
    }
    encrypting = false;
  } else {
    ++encrypt_collisions;
  }
}

// 8Hz held key maintenance, keeping the reciever keystates valid
static void handler_maintenance(nrf_drv_rtc_int_type_t int_type) {
  send_data();
  check_power();
}

// 1000Hz debounce sampling
static void handler_debounce(nrf_drv_rtc_int_type_t int_type) {
  read_keys();

  // debouncing, waits until there have been no transitions in 5ms (assuming
  // five 1ms ticks)
  if (debouncing) {
    // if debouncing, check if current keystates equal to the snapshot
    if (compare_keys(keys_snapshot, keys_buffer, ROWS)) {
      // DEBOUNCE ticks of stable sampling needed before sending data
      debounce_ticks++;
      if (debounce_ticks == DEBOUNCE) {
        for (int j = 0; j < ROWS; j++) {
          keys[j] = keys_snapshot[j];
        }
        send_data();
      }
    } else {
      // if keys change, start period again
      debouncing = false;
    }
  } else {
    // if the keystate is different from the last data
    // sent to the receiver, start debouncing
    if (!compare_keys(keys, keys_buffer, ROWS)) {
      for (int k = 0; k < ROWS; k++) {
        keys_snapshot[k] = keys_buffer[k];
      }
      debouncing = true;
      debounce_ticks = 0;
    }
  }

  // looking for 500 ticks of no keys pressed, to go back to deep sleep
  if (empty_keys()) {
    activity_ticks++;
    if (activity_ticks > ACTIVITY) {
      nrf_drv_rtc_disable(&rtc_maint);
      nrf_drv_rtc_disable(&rtc_deb);
      nrf_gpio_pin_set(R01);
      nrf_gpio_pin_set(R02);
      nrf_gpio_pin_set(R03);
      nrf_gpio_pin_set(R04);
      nrf_gpio_pin_set(R05);
    }

  } else {
    activity_ticks = 0;
  }
}

// Low frequency clock configuration
static void lfclk_config(void) {
  nrf_drv_clock_init();

  nrf_drv_clock_lfclk_request(NULL);
}

// RTC peripheral configuration
static void rtc_config(void) {
  // Initialize RTC instance
  nrf_drv_rtc_init(&rtc_maint, NULL, handler_maintenance);
  nrf_drv_rtc_init(&rtc_deb, NULL, handler_debounce);

  // Enable tick event & interrupt
  nrf_drv_rtc_tick_enable(&rtc_maint, true);
  nrf_drv_rtc_tick_enable(&rtc_deb, true);

  // Power on RTC instance
  nrf_drv_rtc_enable(&rtc_maint);
  nrf_drv_rtc_enable(&rtc_deb);
}

int main() {
  // Initialize Gazell
  nrf_gzll_init(NRF_GZLL_MODE_DEVICE);

  // Attempt sending every packet up to 100 times
  nrf_gzll_set_max_tx_attempts(100);

  // Addressing
  nrf_gzll_set_base_address_0(0x01020304);
  nrf_gzll_set_base_address_1(0x05060708);

  // Enable Gazell to start sending over the air
  nrf_gzll_enable();

  adc_config();

  // Configure 32kHz xtal oscillator
  lfclk_config();

  // Configure RTC peripherals with ticks
  rtc_config();

  // Configure all keys as inputs with pullups
  gpio_config();

  // Set the GPIOTE PORT event as interrupt source, and enable interrupts for
  // GPIOTE
  NRF_GPIOTE->INTENSET = GPIOTE_INTENSET_PORT_Msk;
  NVIC_EnableIRQ(GPIOTE_IRQn);

#ifdef COMPILE_LEFT
  mitosis_crypto_init(&crypto, left_keyboard_crypto_key);
#elif defined(COMPILE_RIGHT)
  mitosis_crypto_init(&crypto, right_keyboard_crypto_key);
#else
#error "no keyboard half specified"
#endif
  mitosis_crypto_init(&receiver_crypto, receiver_crypto_key);

  // Main loop, constantly sleep, waiting for RTC and gpio IRQs
  while (1) {
    __SEV();
    __WFE();
    __WFE();
  }
}

// This handler will be run after wakeup from system ON (GPIO wakeup)
void GPIOTE_IRQHandler(void) {
  if (NRF_GPIOTE->EVENTS_PORT) {
    // clear wakeup event
    NRF_GPIOTE->EVENTS_PORT = 0;

    // enable rtc interupt triggers
    nrf_drv_rtc_enable(&rtc_maint);
    nrf_drv_rtc_enable(&rtc_deb);

    // nrf_gpio_pin_clear(R01);
    // nrf_gpio_pin_clear(R02);
    // nrf_gpio_pin_clear(R03);
    // nrf_gpio_pin_clear(R04);
    // nrf_gpio_pin_clear(R05);

    // TODO: proper interrupt handling to avoid fake interrupts because of
    // matrix scanning debouncing = false; debounce_ticks = 0;
    activity_ticks = 0;
  }
}

/*****************************************************************************/
/** Gazell callback function definitions  */
/*****************************************************************************/

void nrf_gzll_device_tx_success(uint32_t pipe,
                                nrf_gzll_device_tx_info_t tx_info) {
  uint32_t ack_payload_length = sizeof(ack_payload);
  uint8_t mac_scratch[MITOSIS_CMAC_OUTPUT_SIZE];

  if (pipe != PIPE_NUMBER) {
    // Ignore responses from the wrong pipe (shouldn't happen).
    return;
  }
  if (tx_info.payload_received_in_ack) {
    // If the receiver sent back payload, it's a new seed for encryption keys.
    // Collect this packet and validate.
    nrf_gzll_fetch_packet_from_rx_fifo(pipe, (uint8_t*)&ack_payload,
                                       &ack_payload_length);
    mitosis_cmac_compute(&receiver_crypto.cmac, ack_payload.payload,
                         sizeof(ack_payload.payload), mac_scratch);
    if (memcmp(mac_scratch, ack_payload.mac, sizeof(mac_scratch)) == 0) {
      ++rekey_cmac_success;
      receiver_crypto.encrypt.ctr.iv.counter = ack_payload.key_id;
      if (mitosis_aes_ctr_decrypt(&receiver_crypto.encrypt,
                                  sizeof(ack_payload.seed), ack_payload.seed,
                                  mac_scratch)) {
        // The seed packet validates! update the encryption keys.
        data_payload.key_id = ack_payload.key_id;

#ifdef COMPILE_LEFT
        mitosis_crypto_rekey(&crypto, left_keyboard_crypto_key, mac_scratch,
                             sizeof(ack_payload.seed));
#elif defined(COMPILE_RIGHT)
        mitosis_crypto_rekey(&crypto, right_keyboard_crypto_key, mac_scratch,
                             sizeof(ack_payload.seed));
#endif
      } else {
        ++rekey_decrypt_failure;
      }
    } else {
      ++rekey_cmac_failure;
    }
  }
  if (tx_info.num_tx_attempts > max_rtx) {
    max_rtx = tx_info.num_tx_attempts;
  }
  rtx_count += tx_info.num_tx_attempts;
}

// no action is taken when a packet fails to send, this might need to change
void nrf_gzll_device_tx_failed(uint32_t pipe,
                               nrf_gzll_device_tx_info_t tx_info) {}

// Callbacks not needed
void nrf_gzll_host_rx_data_ready(uint32_t pipe,
                                 nrf_gzll_host_rx_info_t rx_info) {}
void nrf_gzll_disabled() {}
