#include "blink.h"

typedef struct {
    char        sym;
    const char *code;
} morse_entry_t;

/* International Morse. '{' and '}' ride on the standard parenthesis codes
 * (KN and KK), so the whole alphabet stays conventional. */
static const morse_entry_t morse_table[] = {
    { 'a', ".-"      }, { 'b', "-..."    }, { 'c', "-.-."    }, { 'd', "-.."     },
    { 'e', "."       }, { 'f', "..-."    }, { 'g', "--."     }, { 'h', "...."    },
    { 'i', ".."      }, { 'j', ".---"    }, { 'k', "-.-"     }, { 'l', ".-.."    },
    { 'm', "--"      }, { 'n', "-."      }, { 'o', "---"     }, { 'p', ".--."    },
    { 'q', "--.-"    }, { 'r', ".-."     }, { 's', "..."     }, { 't', "-"       },
    { 'u', "..-"     }, { 'v', "...-"    }, { 'w', ".--"     }, { 'x', "-..-"    },
    { 'y', "-.--"    }, { 'z', "--.."    },
    { '0', "-----"   }, { '1', ".----"   }, { '2', "..---"   }, { '3', "...--"   },
    { '4', "....-"   }, { '5', "....."   }, { '6', "-...."   }, { '7', "--..."   },
    { '8', "---.."   }, { '9', "----."   },
    { '{', "-.--."   }, { '}', "-.--.-"  }, { '_', "..--.-"  }, { '-', "-....-"  },
    { '.', ".-.-.-"  }, { ',', "--..--"  }, { '?', "..--.."  }, { '!', "-.-.--"  },
    { '/', "-..-."   }, { ':', "---..."  }, { ';', "-.-.-."  }, { '=', "-...-"   },
    { '+', ".-.-."   }, { '&', ".-..."   }, { '@', ".--.-."  }, { '$', "...-..-" },
    { '\'', ".----." }, { '"', ".-..-."  },
};

#define MORSE_TABLE_LEN (sizeof(morse_table) / sizeof(morse_table[0]))

void morse_out(int level)
{
    MORSE_PORT->BSRR = level ? (1u << MORSE_PIN) : (1u << (MORSE_PIN + 16u));
}

static char lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static const char *morse_lookup(char c)
{
    c = lower(c);
    for (uint32_t i = 0u; i < MORSE_TABLE_LEN; i++) {
        if (morse_table[i].sym == c) {
            return morse_table[i].code;
        }
    }
    return 0;
}

static void morse_symbol(const char *code)
{
    for (const char *p = code; *p != '\0'; p++) {
        morse_out(1);
        delay_ms(*p == '-' ? MORSE_DASH_MS : MORSE_DOT_MS);
        morse_out(0);
        delay_ms(MORSE_GAP_MS);
    }
}

/* Reads the flag straight out of its flash block, one character at a
 * time. The volatile pointer keeps the compiler from folding the contents
 * into the dumped region. */
void morse_send(const volatile char *s, uint32_t max_len)
{
    for (uint32_t i = 0u; i < max_len; i++) {
        char c = s[i];

        if (c == '\0' || c == (char)0xFF) {
            return;
        }

        if (c == ' ') {
            /* A letter gap has already elapsed, top it up to a word gap. */
            delay_ms(MORSE_WORD_MS - MORSE_LETTER_MS);
        } else {
            const char *code = morse_lookup(c);
            if (code != 0) {
                morse_symbol(code);
                /* One gap already elapsed after the last element. */
                delay_ms(MORSE_LETTER_MS - MORSE_GAP_MS);
            }
        }
    }
}
