#ifndef _LED_CONFIG_H_
#define _LED_CONFIG_H_

#ifndef u8
#define u8 unsigned char
#endif

#ifndef u16
#define u16 unsigned short
#endif

#ifndef u32
#define u32 unsigned int
#endif

#ifndef u64
#define u64 unsigned long long
#endif

#ifndef s8
#define s8 char
#endif

#ifndef s16
#define s16 short
#endif

#ifndef s32
#define s32 int
#endif

#ifndef s64
#define s64 long long
#endif

extern const unsigned char ledproc_special_led[];
extern void phy_led_config(int unit);

#endif