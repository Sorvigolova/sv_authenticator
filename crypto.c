/*
 *  FIPS-197 compliant AES implementation
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

//
// The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
// http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
// http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
//

//
// The SHA-1 standard was published by NIST in 1993.
// http://www.itl.nist.gov/fipspubs/fip180-1.htm
//

#include "crypto.h"

//
// 32-bit integer manipulation macros (little endian)
//
#define GET_UINT32_LE(n, b, i) { \
		(n) = \
			((uint32_t)(b)[(i) + 0]) | \
			((uint32_t)(b)[(i) + 1] << 8) | \
			((uint32_t)(b)[(i) + 2] << 16) | \
			((uint32_t)(b)[(i) + 3] << 24); \
	}

#define PUT_UINT32_LE(n, b, i) { \
		(b)[(i) + 0] = (uint8_t)((n)); \
		(b)[(i) + 1] = (uint8_t)((n) >> 8); \
		(b)[(i) + 2] = (uint8_t)((n) >> 16); \
		(b)[(i) + 3] = (uint8_t)((n) >> 24); \
	}

//
// 32-bit integer manipulation macros (big endian)
//
#define GET_UINT32_BE(n, b, i) { \
		(n) = \
			((uint32_t)(b)[(i) + 0] << 24) | \
			((uint32_t)(b)[(i) + 1] << 16) | \
			((uint32_t)(b)[(i) + 2] << 8) | \
			((uint32_t)(b)[(i) + 3]); \
	}

#define PUT_UINT32_BE(n, b, i) { \
		(b)[(i) + 0] = (uint8_t)((n) >> 24); \
		(b)[(i) + 1] = (uint8_t)((n) >> 16); \
		(b)[(i) + 2] = (uint8_t)((n) >> 8); \
		(b)[(i) + 3] = (uint8_t)((n)); \
	}

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

//
// Forward S-box
//
static const uint8_t fsb[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

//
// Forward tables
//
#define FT \
	V(A5, 63, 63, C6), V(84, 7C, 7C, F8), V(99, 77, 77, EE), V(8D, 7B, 7B, F6), \
	V(0D, F2, F2, FF), V(BD, 6B, 6B, D6), V(B1, 6F, 6F, DE), V(54, C5, C5, 91), \
	V(50, 30, 30, 60), V(03, 01, 01, 02), V(A9, 67, 67, CE), V(7D, 2B, 2B, 56), \
	V(19, FE, FE, E7), V(62, D7, D7, B5), V(E6, AB, AB, 4D), V(9A, 76, 76, EC), \
	V(45, CA, CA, 8F), V(9D, 82, 82, 1F), V(40, C9, C9, 89), V(87, 7D, 7D, FA), \
	V(15, FA, FA, EF), V(EB, 59, 59, B2), V(C9, 47, 47, 8E), V(0B, F0, F0, FB), \
	V(EC, AD, AD, 41), V(67, D4, D4, B3), V(FD, A2, A2, 5F), V(EA, AF, AF, 45), \
	V(BF, 9C, 9C, 23), V(F7, A4, A4, 53), V(96, 72, 72, E4), V(5B, C0, C0, 9B), \
	V(C2, B7, B7, 75), V(1C, FD, FD, E1), V(AE, 93, 93, 3D), V(6A, 26, 26, 4C), \
	V(5A, 36, 36, 6C), V(41, 3F, 3F, 7E), V(02, F7, F7, F5), V(4F, CC, CC, 83), \
	V(5C, 34, 34, 68), V(F4, A5, A5, 51), V(34, E5, E5, D1), V(08, F1, F1, F9), \
	V(93, 71, 71, E2), V(73, D8, D8, AB), V(53, 31, 31, 62), V(3F, 15, 15, 2A), \
	V(0C, 04, 04, 08), V(52, C7, C7, 95), V(65, 23, 23, 46), V(5E, C3, C3, 9D), \
	V(28, 18, 18, 30), V(A1, 96, 96, 37), V(0F, 05, 05, 0A), V(B5, 9A, 9A, 2F), \
	V(09, 07, 07, 0E), V(36, 12, 12, 24), V(9B, 80, 80, 1B), V(3D, E2, E2, DF), \
	V(26, EB, EB, CD), V(69, 27, 27, 4E), V(CD, B2, B2, 7F), V(9F, 75, 75, EA), \
	V(1B, 09, 09, 12), V(9E, 83, 83, 1D), V(74, 2C, 2C, 58), V(2E, 1A, 1A, 34), \
	V(2D, 1B, 1B, 36), V(B2, 6E, 6E, DC), V(EE, 5A, 5A, B4), V(FB, A0, A0, 5B), \
	V(F6, 52, 52, A4), V(4D, 3B, 3B, 76), V(61, D6, D6, B7), V(CE, B3, B3, 7D), \
	V(7B, 29, 29, 52), V(3E, E3, E3, DD), V(71, 2F, 2F, 5E), V(97, 84, 84, 13), \
	V(F5, 53, 53, A6), V(68, D1, D1, B9), V(00, 00, 00, 00), V(2C, ED, ED, C1), \
	V(60, 20, 20, 40), V(1F, FC, FC, E3), V(C8, B1, B1, 79), V(ED, 5B, 5B, B6), \
	V(BE, 6A, 6A, D4), V(46, CB, CB, 8D), V(D9, BE, BE, 67), V(4B, 39, 39, 72), \
	V(DE, 4A, 4A, 94), V(D4, 4C, 4C, 98), V(E8, 58, 58, B0), V(4A, CF, CF, 85), \
	V(6B, D0, D0, BB), V(2A, EF, EF, C5), V(E5, AA, AA, 4F), V(16, FB, FB, ED), \
	V(C5, 43, 43, 86), V(D7, 4D, 4D, 9A), V(55, 33, 33, 66), V(94, 85, 85, 11), \
	V(CF, 45, 45, 8A), V(10, F9, F9, E9), V(06, 02, 02, 04), V(81, 7F, 7F, FE), \
	V(F0, 50, 50, A0), V(44, 3C, 3C, 78), V(BA, 9F, 9F, 25), V(E3, A8, A8, 4B), \
	V(F3, 51, 51, A2), V(FE, A3, A3, 5D), V(C0, 40, 40, 80), V(8A, 8F, 8F, 05), \
	V(AD, 92, 92, 3F), V(BC, 9D, 9D, 21), V(48, 38, 38, 70), V(04, F5, F5, F1), \
	V(DF, BC, BC, 63), V(C1, B6, B6, 77), V(75, DA, DA, AF), V(63, 21, 21, 42), \
	V(30, 10, 10, 20), V(1A, FF, FF, E5), V(0E, F3, F3, FD), V(6D, D2, D2, BF), \
	V(4C, CD, CD, 81), V(14, 0C, 0C, 18), V(35, 13, 13, 26), V(2F, EC, EC, C3), \
	V(E1, 5F, 5F, BE), V(A2, 97, 97, 35), V(CC, 44, 44, 88), V(39, 17, 17, 2E), \
	V(57, C4, C4, 93), V(F2, A7, A7, 55), V(82, 7E, 7E, FC), V(47, 3D, 3D, 7A), \
	V(AC, 64, 64, C8), V(E7, 5D, 5D, BA), V(2B, 19, 19, 32), V(95, 73, 73, E6), \
	V(A0, 60, 60, C0), V(98, 81, 81, 19), V(D1, 4F, 4F, 9E), V(7F, DC, DC, A3), \
	V(66, 22, 22, 44), V(7E, 2A, 2A, 54), V(AB, 90, 90, 3B), V(83, 88, 88, 0B), \
	V(CA, 46, 46, 8C), V(29, EE, EE, C7), V(D3, B8, B8, 6B), V(3C, 14, 14, 28), \
	V(79, DE, DE, A7), V(E2, 5E, 5E, BC), V(1D, 0B, 0B, 16), V(76, DB, DB, AD), \
	V(3B, E0, E0, DB), V(56, 32, 32, 64), V(4E, 3A, 3A, 74), V(1E, 0A, 0A, 14), \
	V(DB, 49, 49, 92), V(0A, 06, 06, 0C), V(6C, 24, 24, 48), V(E4, 5C, 5C, B8), \
	V(5D, C2, C2, 9F), V(6E, D3, D3, BD), V(EF, AC, AC, 43), V(A6, 62, 62, C4), \
	V(A8, 91, 91, 39), V(A4, 95, 95, 31), V(37, E4, E4, D3), V(8B, 79, 79, F2), \
	V(32, E7, E7, D5), V(43, C8, C8, 8B), V(59, 37, 37, 6E), V(B7, 6D, 6D, DA), \
	V(8C, 8D, 8D, 01), V(64, D5, D5, B1), V(D2, 4E, 4E, 9C), V(E0, A9, A9, 49), \
	V(B4, 6C, 6C, D8), V(FA, 56, 56, AC), V(07, F4, F4, F3), V(25, EA, EA, CF), \
	V(AF, 65, 65, CA), V(8E, 7A, 7A, F4), V(E9, AE, AE, 47), V(18, 08, 08, 10), \
	V(D5, BA, BA, 6F), V(88, 78, 78, F0), V(6F, 25, 25, 4A), V(72, 2E, 2E, 5C), \
	V(24, 1C, 1C, 38), V(F1, A6, A6, 57), V(C7, B4, B4, 73), V(51, C6, C6, 97), \
	V(23, E8, E8, CB), V(7C, DD, DD, A1), V(9C, 74, 74, E8), V(21, 1F, 1F, 3E), \
	V(DD, 4B, 4B, 96), V(DC, BD, BD, 61), V(86, 8B, 8B, 0D), V(85, 8A, 8A, 0F), \
	V(90, 70, 70, E0), V(42, 3E, 3E, 7C), V(C4, B5, B5, 71), V(AA, 66, 66, CC), \
	V(D8, 48, 48, 90), V(05, 03, 03, 06), V(01, F6, F6, F7), V(12, 0E, 0E, 1C), \
	V(A3, 61, 61, C2), V(5F, 35, 35, 6A), V(F9, 57, 57, AE), V(D0, B9, B9, 69), \
	V(91, 86, 86, 17), V(58, C1, C1, 99), V(27, 1D, 1D, 3A), V(B9, 9E, 9E, 27), \
	V(38, E1, E1, D9), V(13, F8, F8, EB), V(B3, 98, 98, 2B), V(33, 11, 11, 22), \
	V(BB, 69, 69, D2), V(70, D9, D9, A9), V(89, 8E, 8E, 07), V(A7, 94, 94, 33), \
	V(B6, 9B, 9B, 2D), V(22, 1E, 1E, 3C), V(92, 87, 87, 15), V(20, E9, E9, C9), \
	V(49, CE, CE, 87), V(FF, 55, 55, AA), V(78, 28, 28, 50), V(7A, DF, DF, A5), \
	V(8F, 8C, 8C, 03), V(F8, A1, A1, 59), V(80, 89, 89, 09), V(17, 0D, 0D, 1A), \
	V(DA, BF, BF, 65), V(31, E6, E6, D7), V(C6, 42, 42, 84), V(B8, 68, 68, D0), \
	V(C3, 41, 41, 82), V(B0, 99, 99, 29), V(77, 2D, 2D, 5A), V(11, 0F, 0F, 1E), \
	V(CB, B0, B0, 7B), V(FC, 54, 54, A8), V(D6, BB, BB, 6D), V(3A, 16, 16, 2C)

#define V(a, b, c, d) 0x##a##b##c##d
static const uint32_t ft0[256] = { FT };
#undef V

#define V(a, b, c, d) 0x##b##c##d##a
static const uint32_t ft1[256] = { FT };
#undef V

#define V(a, b, c, d) 0x##c##d##a##b
static const uint32_t ft2[256] = { FT };
#undef V

#define V(a, b, c, d) 0x##d##a##b##c
static const uint32_t ft3[256] = { FT };
#undef V

#undef FT

//
// Reverse S-box
//
static const uint8_t rsb[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
	0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
	0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
	0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
	0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
	0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
	0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
	0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
	0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
	0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
	0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
	0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
	0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
	0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
	0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
	0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

//
// Reverse tables
//
#define RT \
	V(50, A7, F4, 51), V(53, 65, 41, 7E), V(C3, A4, 17, 1A), V(96, 5E, 27, 3A), \
	V(CB, 6B, AB, 3B), V(F1, 45, 9D, 1F), V(AB, 58, FA, AC), V(93, 03, E3, 4B), \
	V(55, FA, 30, 20), V(F6, 6D, 76, AD), V(91, 76, CC, 88), V(25, 4C, 02, F5), \
	V(FC, D7, E5, 4F), V(D7, CB, 2A, C5), V(80, 44, 35, 26), V(8F, A3, 62, B5), \
	V(49, 5A, B1, DE), V(67, 1B, BA, 25), V(98, 0E, EA, 45), V(E1, C0, FE, 5D), \
	V(02, 75, 2F, C3), V(12, F0, 4C, 81), V(A3, 97, 46, 8D), V(C6, F9, D3, 6B), \
	V(E7, 5F, 8F, 03), V(95, 9C, 92, 15), V(EB, 7A, 6D, BF), V(DA, 59, 52, 95), \
	V(2D, 83, BE, D4), V(D3, 21, 74, 58), V(29, 69, E0, 49), V(44, C8, C9, 8E), \
	V(6A, 89, C2, 75), V(78, 79, 8E, F4), V(6B, 3E, 58, 99), V(DD, 71, B9, 27), \
	V(B6, 4F, E1, BE), V(17, AD, 88, F0), V(66, AC, 20, C9), V(B4, 3A, CE, 7D), \
	V(18, 4A, DF, 63), V(82, 31, 1A, E5), V(60, 33, 51, 97), V(45, 7F, 53, 62), \
	V(E0, 77, 64, B1), V(84, AE, 6B, BB), V(1C, A0, 81, FE), V(94, 2B, 08, F9), \
	V(58, 68, 48, 70), V(19, FD, 45, 8F), V(87, 6C, DE, 94), V(B7, F8, 7B, 52), \
	V(23, D3, 73, AB), V(E2, 02, 4B, 72), V(57, 8F, 1F, E3), V(2A, AB, 55, 66), \
	V(07, 28, EB, B2), V(03, C2, B5, 2F), V(9A, 7B, C5, 86), V(A5, 08, 37, D3), \
	V(F2, 87, 28, 30), V(B2, A5, BF, 23), V(BA, 6A, 03, 02), V(5C, 82, 16, ED), \
	V(2B, 1C, CF, 8A), V(92, B4, 79, A7), V(F0, F2, 07, F3), V(A1, E2, 69, 4E), \
	V(CD, F4, DA, 65), V(D5, BE, 05, 06), V(1F, 62, 34, D1), V(8A, FE, A6, C4), \
	V(9D, 53, 2E, 34), V(A0, 55, F3, A2), V(32, E1, 8A, 05), V(75, EB, F6, A4), \
	V(39, EC, 83, 0B), V(AA, EF, 60, 40), V(06, 9F, 71, 5E), V(51, 10, 6E, BD), \
	V(F9, 8A, 21, 3E), V(3D, 06, DD, 96), V(AE, 05, 3E, DD), V(46, BD, E6, 4D), \
	V(B5, 8D, 54, 91), V(05, 5D, C4, 71), V(6F, D4, 06, 04), V(FF, 15, 50, 60), \
	V(24, FB, 98, 19), V(97, E9, BD, D6), V(CC, 43, 40, 89), V(77, 9E, D9, 67), \
	V(BD, 42, E8, B0), V(88, 8B, 89, 07), V(38, 5B, 19, E7), V(DB, EE, C8, 79), \
	V(47, 0A, 7C, A1), V(E9, 0F, 42, 7C), V(C9, 1E, 84, F8), V(00, 00, 00, 00), \
	V(83, 86, 80, 09), V(48, ED, 2B, 32), V(AC, 70, 11, 1E), V(4E, 72, 5A, 6C), \
	V(FB, FF, 0E, FD), V(56, 38, 85, 0F), V(1E, D5, AE, 3D), V(27, 39, 2D, 36), \
	V(64, D9, 0F, 0A), V(21, A6, 5C, 68), V(D1, 54, 5B, 9B), V(3A, 2E, 36, 24), \
	V(B1, 67, 0A, 0C), V(0F, E7, 57, 93), V(D2, 96, EE, B4), V(9E, 91, 9B, 1B), \
	V(4F, C5, C0, 80), V(A2, 20, DC, 61), V(69, 4B, 77, 5A), V(16, 1A, 12, 1C), \
	V(0A, BA, 93, E2), V(E5, 2A, A0, C0), V(43, E0, 22, 3C), V(1D, 17, 1B, 12), \
	V(0B, 0D, 09, 0E), V(AD, C7, 8B, F2), V(B9, A8, B6, 2D), V(C8, A9, 1E, 14), \
	V(85, 19, F1, 57), V(4C, 07, 75, AF), V(BB, DD, 99, EE), V(FD, 60, 7F, A3), \
	V(9F, 26, 01, F7), V(BC, F5, 72, 5C), V(C5, 3B, 66, 44), V(34, 7E, FB, 5B), \
	V(76, 29, 43, 8B), V(DC, C6, 23, CB), V(68, FC, ED, B6), V(63, F1, E4, B8), \
	V(CA, DC, 31, D7), V(10, 85, 63, 42), V(40, 22, 97, 13), V(20, 11, C6, 84), \
	V(7D, 24, 4A, 85), V(F8, 3D, BB, D2), V(11, 32, F9, AE), V(6D, A1, 29, C7), \
	V(4B, 2F, 9E, 1D), V(F3, 30, B2, DC), V(EC, 52, 86, 0D), V(D0, E3, C1, 77), \
	V(6C, 16, B3, 2B), V(99, B9, 70, A9), V(FA, 48, 94, 11), V(22, 64, E9, 47), \
	V(C4, 8C, FC, A8), V(1A, 3F, F0, A0), V(D8, 2C, 7D, 56), V(EF, 90, 33, 22), \
	V(C7, 4E, 49, 87), V(C1, D1, 38, D9), V(FE, A2, CA, 8C), V(36, 0B, D4, 98), \
	V(CF, 81, F5, A6), V(28, DE, 7A, A5), V(26, 8E, B7, DA), V(A4, BF, AD, 3F), \
	V(E4, 9D, 3A, 2C), V(0D, 92, 78, 50), V(9B, CC, 5F, 6A), V(62, 46, 7E, 54), \
	V(C2, 13, 8D, F6), V(E8, B8, D8, 90), V(5E, F7, 39, 2E), V(F5, AF, C3, 82), \
	V(BE, 80, 5D, 9F), V(7C, 93, D0, 69), V(A9, 2D, D5, 6F), V(B3, 12, 25, CF), \
	V(3B, 99, AC, C8), V(A7, 7D, 18, 10), V(6E, 63, 9C, E8), V(7B, BB, 3B, DB), \
	V(09, 78, 26, CD), V(F4, 18, 59, 6E), V(01, B7, 9A, EC), V(A8, 9A, 4F, 83), \
	V(65, 6E, 95, E6), V(7E, E6, FF, AA), V(08, CF, BC, 21), V(E6, E8, 15, EF), \
	V(D9, 9B, E7, BA), V(CE, 36, 6F, 4A), V(D4, 09, 9F, EA), V(D6, 7C, B0, 29), \
	V(AF, B2, A4, 31), V(31, 23, 3F, 2A), V(30, 94, A5, C6), V(C0, 66, A2, 35), \
	V(37, BC, 4E, 74), V(A6, CA, 82, FC), V(B0, D0, 90, E0), V(15, D8, A7, 33), \
	V(4A, 98, 04, F1), V(F7, DA, EC, 41), V(0E, 50, CD, 7F), V(2F, F6, 91, 17), \
	V(8D, D6, 4D, 76), V(4D, B0, EF, 43), V(54, 4D, AA, CC), V(DF, 04, 96, E4), \
	V(E3, B5, D1, 9E), V(1B, 88, 6A, 4C), V(B8, 1F, 2C, C1), V(7F, 51, 65, 46), \
	V(04, EA, 5E, 9D), V(5D, 35, 8C, 01), V(73, 74, 87, FA), V(2E, 41, 0B, FB), \
	V(5A, 1D, 67, B3), V(52, D2, DB, 92), V(33, 56, 10, E9), V(13, 47, D6, 6D), \
	V(8C, 61, D7, 9A), V(7A, 0C, A1, 37), V(8E, 14, F8, 59), V(89, 3C, 13, EB), \
	V(EE, 27, A9, CE), V(35, C9, 61, B7), V(ED, E5, 1C, E1), V(3C, B1, 47, 7A), \
	V(59, DF, D2, 9C), V(3F, 73, F2, 55), V(79, CE, 14, 18), V(BF, 37, C7, 73), \
	V(EA, CD, F7, 53), V(5B, AA, FD, 5F), V(14, 6F, 3D, DF), V(86, DB, 44, 78), \
	V(81, F3, AF, CA), V(3E, C4, 68, B9), V(2C, 34, 24, 38), V(5F, 40, A3, C2), \
	V(72, C3, 1D, 16), V(0C, 25, E2, BC), V(8B, 49, 3C, 28), V(41, 95, 0D, FF), \
	V(71, 01, A8, 39), V(DE, B3, 0C, 08), V(9C, E4, B4, D8), V(90, C1, 56, 64), \
	V(61, 84, CB, 7B), V(70, B6, 32, D5), V(74, 5C, 6C, 48), V(42, 57, B8, D0)

#define V(a, b, c, d) 0x##a##b##c##d
static const uint32_t rt0[256] = { RT };
#undef V

#define V(a, b, c, d) 0x##b##c##d##a
static const uint32_t rt1[256] = { RT };
#undef V

#define V(a, b, c, d) 0x##c##d##a##b
static const uint32_t rt2[256] = { RT };
#undef V

#define V(a, b, c, d) 0x##d##a##b##c
static const uint32_t rt3[256] = { RT };
#undef V

#undef RT

//
// Round constants
//
static const uint32_t rcon[10] = {
	0x00000001, 0x00000002, 0x00000004, 0x00000008,
	0x00000010, 0x00000020, 0x00000040, 0x00000080,
	0x0000001B, 0x00000036,
};

int aes_init(struct aes_context_t* const ctx, const int mode, const uint8_t* const key, const uint32_t key_size) {
	if (mode != AES_DECRYPT && mode != AES_ENCRYPT)
		return ERROR_INVALID_MODE;

	switch (key_size) {
		case 128: ctx->nr = 10; break;
		case 192: ctx->nr = 12; break;
		case 256: ctx->nr = 14; break;
		default:
			return ERROR_INVALID_KEY_SIZE;
	}

	if (mode == AES_ENCRYPT) {
		uint32_t* rk;

		int i;
	
		ctx->rk = rk = ctx->buf;

		for (i = 0; i < (key_size >> 5); ++i) {
			GET_UINT32_LE(rk[i], key, i << 2);
		}

		switch (ctx->nr) {
			case 10:
				for (i = 0; i < 10; ++i, rk += 4) {
					rk[4] = rk[0] ^ rcon[i] ^
						((uint32_t)fsb[(rk[3] >> 8) & 0xFF]) ^
						((uint32_t)fsb[(rk[3] >> 16) & 0xFF] << 8) ^
						((uint32_t)fsb[(rk[3] >> 24) & 0xFF] << 16) ^
						((uint32_t)fsb[(rk[3]) & 0xFF] << 24);
					rk[5] = rk[1] ^ rk[4];
					rk[6] = rk[2] ^ rk[5];
					rk[7] = rk[3] ^ rk[6];
				}
				break;

			case 12:
				for (i = 0; i < 8; ++i, rk += 6) {
					rk[6] = rk[0] ^ rcon[i] ^
						((uint32_t)fsb[(rk[5] >> 8) & 0xFF]) ^
						((uint32_t)fsb[(rk[5] >> 16) & 0xFF] << 8) ^
						((uint32_t)fsb[(rk[5] >> 24) & 0xFF] << 16) ^
						((uint32_t)fsb[(rk[5]) & 0xFF] << 24);
					rk[7] = rk[1] ^ rk[6];
					rk[8] = rk[2] ^ rk[7];
					rk[9] = rk[3] ^ rk[8];
					rk[10] = rk[4] ^ rk[9];
					rk[11] = rk[5] ^ rk[10];
				}
				break;

			case 14:
				for (i = 0; i < 7; ++i, rk += 8) {
					rk[8] = rk[0] ^ rcon[i] ^
						((uint32_t)fsb[(rk[7] >>  8) & 0xFF]) ^
						((uint32_t)fsb[(rk[7] >> 16) & 0xFF] << 8) ^
						((uint32_t)fsb[(rk[7] >> 24) & 0xFF] << 16) ^
						((uint32_t)fsb[(rk[7]) & 0xFF] << 24);
					rk[9] = rk[1] ^ rk[8];
					rk[10] = rk[2] ^ rk[9];
					rk[11] = rk[3] ^ rk[10];
					rk[12] = rk[4] ^
						((uint32_t)fsb[(rk[11]) & 0xFF]) ^
						((uint32_t)fsb[(rk[11] >>  8) & 0xFF] << 8) ^
						((uint32_t)fsb[(rk[11] >> 16) & 0xFF] << 16) ^
						((uint32_t)fsb[(rk[11] >> 24) & 0xFF] << 24);
					rk[13] = rk[5] ^ rk[12];
					rk[14] = rk[6] ^ rk[13];
					rk[15] = rk[7] ^ rk[14];
				}
				break;

			default:
				break;
		}
	} else {
		int result;

		struct aes_context_t tmp_ctx;

		uint32_t* rk;
		uint32_t* sk;
		int i, j;

		result = aes_init(&tmp_ctx, AES_ENCRYPT, key, key_size);
		if (result != 0)
			return result;

		ctx->rk = rk = ctx->buf;
		sk = tmp_ctx.rk + tmp_ctx.nr * 4;

		*rk++ = *sk++;
		*rk++ = *sk++;
		*rk++ = *sk++;
		*rk++ = *sk++;

		sk -= 8;
		for (i = ctx->nr - 1; i > 0; --i) {
			for (j = 0; j < 4; ++j, ++sk)
				*rk++ = rt0[fsb[(*sk) & 0xFF]] ^ rt1[fsb[(*sk >> 8) & 0xFF]] ^ rt2[fsb[(*sk >> 16) & 0xFF]] ^ rt3[fsb[(*sk >> 24) & 0xFF]];
			sk -= 8;
		}

		*rk++ = *sk++;
		*rk++ = *sk++;
		*rk++ = *sk++;
		*rk++ = *sk++;
	}

	ctx->mode = mode;

	return 0;
}

int aes_crypt_ecb(struct aes_context_t* const ctx, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE]) {
	uint32_t* rk;

	uint32_t x0, x1, x2, x3;
	uint32_t y0, y1, y2, y3;

	int i;

	rk = ctx->rk;

	GET_UINT32_LE(x0, input, 0); x0 ^= *rk++;
	GET_UINT32_LE(x1, input, 4); x1 ^= *rk++;
	GET_UINT32_LE(x2, input, 8); x2 ^= *rk++;
	GET_UINT32_LE(x3, input, 12); x3 ^= *rk++;

	#define AES_FROUND(x0, x1, x2, x3, y0, y1, y2, y3) { \
			(x0) = *rk++ ^ \
				ft0[(y0) & 0xFF] ^ \
				ft1[(y1 >> 8) & 0xFF] ^ \
				ft2[(y2 >> 16) & 0xFF] ^ \
				ft3[(y3 >> 24) & 0xFF]; \
			(x1) = *rk++ ^ \
				ft0[(y1) & 0xFF] ^ \
				ft1[(y2 >> 8) & 0xFF] ^ \
				ft2[(y3 >> 16) & 0xFF] ^ \
				ft3[(y0 >> 24) & 0xFF]; \
			(x2) = *rk++ ^ \
				ft0[(y2) & 0xFF] ^ \
				ft1[(y3 >> 8) & 0xFF] ^ \
				ft2[(y0 >> 16) & 0xFF] ^ \
				ft3[(y1 >> 24) & 0xFF]; \
			(x3) = *rk++ ^ \
				ft0[(y3) & 0xFF] ^ \
				ft1[(y0 >> 8) & 0xFF] ^ \
				ft2[(y1 >> 16) & 0xFF] ^ \
				ft3[(y2 >> 24) & 0xFF]; \
		}

	#define AES_RROUND(x0, x1, x2, x3, y0, y1, y2, y3) { \
			(x0) = *rk++ ^ \
				rt0[(y0) & 0xFF] ^ \
				rt1[(y3 >>  8) & 0xFF] ^ \
				rt2[(y2 >> 16) & 0xFF] ^ \
				rt3[(y1 >> 24) & 0xFF]; \
			(x1) = *rk++ ^ \
				rt0[(y1) & 0xFF] ^ \
				rt1[(y0 >> 8) & 0xFF] ^ \
				rt2[(y3 >> 16) & 0xFF] ^ \
				rt3[(y2 >> 24) & 0xFF]; \
			(x2) = *rk++ ^ \
				rt0[(y2) & 0xFF] ^ \
				rt1[(y1 >> 8) & 0xFF] ^ \
				rt2[(y0 >> 16) & 0xFF] ^ \
				rt3[(y3 >> 24) & 0xFF]; \
			(x3) = *rk++ ^ \
				rt0[(y3) & 0xFF] ^ \
				rt1[(y2 >> 8) & 0xFF] ^ \
				rt2[(y1 >> 16) & 0xFF] ^ \
				rt3[(y0 >> 24) & 0xFF]; \
		}

	if (ctx->mode == AES_DECRYPT) {
		for (i = (ctx->nr >> 1) - 1; i > 0; --i) {
			AES_RROUND(y0, y1, y2, y3, x0, x1, x2, x3);
			AES_RROUND(x0, x1, x2, x3, y0, y1, y2, y3);
		}

		AES_RROUND(y0, y1, y2, y3, x0, x1, x2, x3);

		x0 = *rk++ ^ \
			((uint32_t)rsb[(y0) & 0xFF]) ^
			((uint32_t)rsb[(y3 >> 8) & 0xFF] << 8) ^
			((uint32_t)rsb[(y2 >> 16) & 0xFF] << 16) ^
			((uint32_t)rsb[(y1 >> 24) & 0xFF] << 24);

		x1 = *rk++ ^ \
			((uint32_t)rsb[(y1) & 0xFF]) ^
			((uint32_t)rsb[(y0 >> 8) & 0xFF] <<  8) ^
			((uint32_t)rsb[(y3 >> 16) & 0xFF] << 16) ^
			((uint32_t)rsb[(y2 >> 24) & 0xFF] << 24);

		x2 = *rk++ ^ \
			((uint32_t)rsb[(y2) & 0xFF]) ^
			((uint32_t)rsb[(y1 >> 8) & 0xFF] << 8) ^
			((uint32_t)rsb[(y0 >> 16) & 0xFF] << 16) ^
			((uint32_t)rsb[(y3 >> 24) & 0xFF] << 24);

		x3 = *rk++ ^ \
			((uint32_t)rsb[(y3) & 0xFF]) ^
			((uint32_t)rsb[(y2 >> 8) & 0xFF] << 8) ^
			((uint32_t)rsb[(y1 >> 16) & 0xFF] << 16) ^
			((uint32_t)rsb[(y0 >> 24) & 0xFF] << 24);
	} else {
		for (i = (ctx->nr >> 1) - 1; i > 0; --i) {
			AES_FROUND(y0, y1, y2, y3, x0, x1, x2, x3);
			AES_FROUND(x0, x1, x2, x3, y0, y1, y2, y3);
		}

		AES_FROUND(y0, y1, y2, y3, x0, x1, x2, x3);

		x0 = *rk++ ^ \
				((uint32_t)fsb[(y0) & 0xFF]) ^
				((uint32_t)fsb[(y1 >> 8) & 0xFF] << 8) ^
				((uint32_t)fsb[(y2 >> 16) & 0xFF] << 16) ^
				((uint32_t)fsb[(y3 >> 24) & 0xFF] << 24);

		x1 = *rk++ ^ \
				((uint32_t)fsb[(y1) & 0xFF]) ^
				((uint32_t)fsb[(y2 >> 8) & 0xFF] << 8) ^
				((uint32_t)fsb[(y3 >> 16) & 0xFF] << 16) ^
				((uint32_t)fsb[(y0 >> 24) & 0xFF] << 24);

		x2 = *rk++ ^ \
				((uint32_t)fsb[(y2) & 0xFF]) ^
				((uint32_t)fsb[(y3 >> 8) & 0xFF] << 8) ^
				((uint32_t)fsb[(y0 >> 16) & 0xFF] << 16) ^
				((uint32_t)fsb[(y1 >> 24) & 0xFF] << 24);

		x3 = *rk++ ^ \
				((uint32_t)fsb[(y3) & 0xFF]) ^
				((uint32_t)fsb[(y0 >> 8) & 0xFF] << 8) ^
				((uint32_t)fsb[(y1 >> 16) & 0xFF] << 16) ^
				((uint32_t)fsb[(y2 >> 24) & 0xFF] << 24);
	}

	#undef AES_FROUND
	#undef AES_RROUND

	PUT_UINT32_LE(x0, output, 0);
	PUT_UINT32_LE(x1, output, 4);
	PUT_UINT32_LE(x2, output, 8);
	PUT_UINT32_LE(x3, output, 12);

	return 0;
}

int aes_encrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	result = aes_init(&ctx, AES_ENCRYPT, key, key_size);
	if (result != 0)
		return result;

	result = aes_crypt_ecb(&ctx, input, output);
	if (result != 0)
		return result;

	return 0;
}

int aes_decrypt_ecb(const uint8_t* const key, const int key_size, const uint8_t input[AES_BLOCK_SIZE], uint8_t output[AES_BLOCK_SIZE], const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	result = aes_init(&ctx, AES_DECRYPT, key, key_size);
	if (result != 0)
		return result;

	result = aes_crypt_ecb(&ctx, input, output);
	if (result != 0)
		return result;

	return 0;
}

int aes_crypt_cbc(struct aes_context_t* const ctx, uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	if (length % AES_BLOCK_SIZE != 0)
		return ERROR_INVALID_DATA_SIZE;

	const uint8_t* src = input;
	uint8_t* dst = output;
	uint32_t size = length;
	int i;

	if (ctx->mode == AES_DECRYPT) {
		uint8_t temp[AES_BLOCK_SIZE];
		while (size > 0) {
			memcpy(temp, src, AES_BLOCK_SIZE);
			aes_crypt_ecb(ctx, src, dst);

			for (i = 0; i < AES_BLOCK_SIZE; ++i)
				dst[i] = dst[i] ^ iv[i];

			memcpy(iv, temp, AES_BLOCK_SIZE);

			src += AES_BLOCK_SIZE;
			dst += AES_BLOCK_SIZE;
			size -= AES_BLOCK_SIZE;
		}
	} else {
		while (size > 0) {
			for (i = 0; i < AES_BLOCK_SIZE; ++i)
				dst[i] = src[i] ^ iv[i];

			aes_crypt_ecb(ctx, dst, dst);
			memcpy(iv, dst, 16);

			src += AES_BLOCK_SIZE;
			dst += AES_BLOCK_SIZE;
			size -= AES_BLOCK_SIZE;
		}
	}

	return 0;
}

int aes_encrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	uint8_t temp[AES_BLOCK_SIZE];

	result = aes_init(&ctx, AES_ENCRYPT, key, key_size);
	if (result != 0)
		return result;

	memcpy(temp, iv, AES_BLOCK_SIZE);

	result = aes_crypt_cbc(&ctx, temp, input, output, length);
	if (result != 0)
		return result;

	return 0;
}

int aes_decrypt_cbc(const uint8_t* const key, const int key_size, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	uint8_t temp[AES_BLOCK_SIZE];

	result = aes_init(&ctx, AES_DECRYPT, key, key_size);
	if (result != 0)
		return result;

	memcpy(temp, iv, AES_BLOCK_SIZE);

	result = aes_crypt_cbc(&ctx, temp, input, output, length);
	if (result != 0)
		return result;

	return 0;
}

int aes_crypt_ctr(struct aes_context_t* const ctx, uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	uint8_t counter[AES_BLOCK_SIZE];
	uint8_t stream_block[AES_BLOCK_SIZE];

	const uint8_t* src = input;
	uint8_t* dst = output;
	uint32_t size = length;
	uint32_t left;
	int i;

	memcpy(counter, nonce, AES_BLOCK_SIZE);
	
	for (left = size; left > 0; ) {
		aes_crypt_ecb(ctx, counter, stream_block);

		size = (left < AES_BLOCK_SIZE) ? left : AES_BLOCK_SIZE;
		for (i = 0; i < size; ++i)
			dst[i] = src[i] ^ stream_block[i];

		src += size;
		dst += size;
		left -= size;

		for (i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
			counter[i]++;
			if (counter[i] != 0)
				break;
		}
	}

	memcpy(nonce, counter, AES_BLOCK_SIZE);

	return 0;
}

int aes_ctr(const uint8_t* const key, const int key_size, const uint8_t nonce[AES_BLOCK_SIZE], const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	uint8_t temp[AES_BLOCK_SIZE];

	result = aes_init(&ctx, AES_ENCRYPT, key, key_size);
	if (result != 0)
		return result;

	memcpy(temp, nonce, AES_BLOCK_SIZE);

	result = aes_crypt_ctr(&ctx, temp, input, output, length);
	if (result != 0)
		return result;

	return 0;
}

int aes_xts_init(struct aes_xts_context_t* const ctx, const int mode, const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size) {
	int result;

	if (mode != AES_DECRYPT && mode != AES_ENCRYPT)
		return ERROR_INVALID_MODE;

	result = aes_init(&ctx->tweak_ctx, AES_ENCRYPT, tweak_key, tweak_key_size);
	if (result != 0)
		return result;

	result = aes_init(&ctx->data_ctx, mode, data_key, data_key_size);
	if (result != 0)
		return result;

	ctx->mode = mode;

	return 0;
}

int aes_crypt_xts(struct aes_xts_context_t* const ctx, const uint8_t* const input, uint8_t* const output, const uint64_t sector_index, const uint32_t sector_size) {
	uint8_t tweak[AES_BLOCK_SIZE];
	uint8_t block[AES_BLOCK_SIZE];

	uint64_t nonce;
	uint32_t carry_in, carry_out;
	int i, j;

	if (sector_size % AES_BLOCK_SIZE != 0)
		return ERROR_INVALID_DATA_SIZE;

	memset(tweak, 0, AES_BLOCK_SIZE);

	nonce = sector_index;
	for (i = 0; i < 8; ++i) {
		tweak[i] = nonce & 0xFF;
		nonce >>= 8;
	}

	aes_crypt_ecb(&ctx->tweak_ctx, tweak, tweak);

	for (i = 0; i < sector_size; i += AES_BLOCK_SIZE) {
		for (j = 0; j < AES_BLOCK_SIZE; ++j)
			block[j] = input[i + j] ^ tweak[j];

		aes_crypt_ecb(&ctx->data_ctx, block, block);

		for (j = 0; j < AES_BLOCK_SIZE; ++j)
			output[i + j] = block[j] ^ tweak[j];

		carry_in = 0; carry_out = 0;
		for (j = 0; j < AES_BLOCK_SIZE; ++j) {
			carry_out = (tweak[j] >> 7) & 1;
			tweak[j] = ((tweak[j] << 1) + carry_in) & 0xFF;
			carry_in = carry_out;
		}
		if (carry_out)
			tweak[0] ^= 0x87;
	}

	return 0;
}

int aes_encrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size) {
	int result;

	struct aes_xts_context_t ctx;

	result = aes_xts_init(&ctx, AES_ENCRYPT, tweak_key, tweak_key_size, data_key, data_key_size);
	if (result != 0)
		return result;

	result = aes_crypt_xts(&ctx, input, output, sector_index, sector_size);
	if (result != 0)
		return result;

	return 0;
}

int aes_decrypt_xts(const uint8_t* const tweak_key, const int tweak_key_size, const uint8_t* const data_key, const int data_key_size, const uint8_t* const input, uint8_t* const output, const uint32_t sector_index, const uint32_t sector_size) {
	int result;

	struct aes_xts_context_t ctx;

	result = aes_xts_init(&ctx, AES_DECRYPT, tweak_key, tweak_key_size, data_key, data_key_size);
	if (result != 0)
		return result;

	result = aes_crypt_xts(&ctx, input, output, sector_index, sector_size);
	if (result != 0)
		return result;

	return 0;
}

static void gf_mulx(uint8_t* const pad) {
	uint32_t carry;
	int i;

	carry = pad[0] & 0x80;
	for (i = 0; i < AES_BLOCK_SIZE - 1; ++i)
		pad[i] = (pad[i] << 1) | (pad[i + 1] >> 7);
	pad[AES_BLOCK_SIZE - 1] <<= 1;
	if (carry)
		pad[AES_BLOCK_SIZE - 1] ^= 0x87;
}

int aes_cmac(const uint8_t* const key, const int key_size, const uint8_t* const input, uint8_t* const output, const uint32_t length) {
	int result;

	struct aes_context_t ctx;

	uint8_t cbc[AES_BLOCK_SIZE];

	int i;

	result = aes_init(&ctx, AES_ENCRYPT, key, key_size);
	if (result != 0)
		return result;

	memset(cbc, 0, AES_BLOCK_SIZE);

	const uint8_t* src = input;
	uint8_t* dst = output;
	uint32_t size = length;

	while (size >= AES_BLOCK_SIZE) {
		for (i = 0; i < AES_BLOCK_SIZE; ++i)
			cbc[i] ^= *src++;

		if (size > AES_BLOCK_SIZE)
			aes_crypt_ecb(&ctx, cbc, cbc);

		size -= AES_BLOCK_SIZE;
	}

	uint8_t pad[AES_BLOCK_SIZE];
	memset(pad, 0, AES_BLOCK_SIZE);
	aes_crypt_ecb(&ctx, pad, pad);
	gf_mulx(pad);

	if (size != 0) {
		for (i = 0; i < size; ++i)
			cbc[i] ^= *src++;
		cbc[size] ^= 0x80;
		gf_mulx(pad);
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
		pad[i] ^= cbc[i];

	aes_crypt_ecb(&ctx, pad, dst);

	return 0;
}

//-----------------------------------------------------------------------------
// SHA-1
//-----------------------------------------------------------------------------

static const uint8_t sha1_padding[SHA1_BLOCK_SIZE] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void sha1_starts(struct sha1_context_t* const ctx) {
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;

	ctx->total[0] = 0;
	ctx->total[1] = 0;
}

void sha1_transform(struct sha1_context_t* const ctx, const uint8_t data[SHA1_BLOCK_SIZE]) {
	uint32_t w[16];

	uint32_t a, b, c, d, e;
	uint32_t temp;

	GET_UINT32_BE(w[0], data, 0);
	GET_UINT32_BE(w[1], data, 4);
	GET_UINT32_BE(w[2], data, 8);
	GET_UINT32_BE(w[3], data, 12);
	GET_UINT32_BE(w[4], data, 16);
	GET_UINT32_BE(w[5], data, 20);
	GET_UINT32_BE(w[6], data, 24);
	GET_UINT32_BE(w[7], data, 28);
	GET_UINT32_BE(w[8], data, 32);
	GET_UINT32_BE(w[9], data, 36);
	GET_UINT32_BE(w[10], data, 40);
	GET_UINT32_BE(w[11], data, 44);
	GET_UINT32_BE(w[12], data, 48);
	GET_UINT32_BE(w[13], data, 52);
	GET_UINT32_BE(w[14], data, 56);
	GET_UINT32_BE(w[15], data, 60);

	#define S(x, n) (((x) << (n)) | (((x) & 0xFFFFFFFF) >> (32 - (n))))

	#define R(t) ( \
			temp = \
				w[(t - 3) & 0x0F] ^ w[(t - 8) & 0x0F] ^ \
				w[(t - 14) & 0x0F] ^ w[t & 0x0F], \
				(w[t & 0x0F] = S(temp, 1)) \
		)

	#define P(a, b, c, d, e, x) { \
			e += S(a, 5) + F(b, c, d) + K + x; \
			b = S(b, 30); \
		}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
	#define K 0x5A827999

	P(a, b, c, d, e, w[0]);
	P(e, a, b, c, d, w[1]);
	P(d, e, a, b, c, w[2]);
	P(c, d, e, a, b, w[3]);
	P(b, c, d, e, a, w[4]);
	P(a, b, c, d, e, w[5]);
	P(e, a, b, c, d, w[6]);
	P(d, e, a, b, c, w[7]);
	P(c, d, e, a, b, w[8]);
	P(b, c, d, e, a, w[9]);
	P(a, b, c, d, e, w[10]);
	P(e, a, b, c, d, w[11]);
	P(d, e, a, b, c, w[12]);
	P(c, d, e, a, b, w[13]);
	P(b, c, d, e, a, w[14]);
	P(a, b, c, d, e, w[15]);
	P(e, a, b, c, d, R(16));
	P(d, e, a, b, c, R(17));
	P(c, d, e, a, b, R(18));
	P(b, c, d, e, a, R(19));

	#undef K
	#undef F

	#define F(x, y, z) ((x) ^ (y) ^ (z))
	#define K 0x6ED9EBA1

	P(a, b, c, d, e, R(20));
	P(e, a, b, c, d, R(21));
	P(d, e, a, b, c, R(22));
	P(c, d, e, a, b, R(23));
	P(b, c, d, e, a, R(24));
	P(a, b, c, d, e, R(25));
	P(e, a, b, c, d, R(26));
	P(d, e, a, b, c, R(27));
	P(c, d, e, a, b, R(28));
	P(b, c, d, e, a, R(29));
	P(a, b, c, d, e, R(30));
	P(e, a, b, c, d, R(31));
	P(d, e, a, b, c, R(32));
	P(c, d, e, a, b, R(33));
	P(b, c, d, e, a, R(34));
	P(a, b, c, d, e, R(35));
	P(e, a, b, c, d, R(36));
	P(d, e, a, b, c, R(37));
	P(c, d, e, a, b, R(38));
	P(b, c, d, e, a, R(39));

	#undef K
	#undef F

	#define F(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
	#define K 0x8F1BBCDC

	P(a, b, c, d, e, R(40));
	P(e, a, b, c, d, R(41));
	P(d, e, a, b, c, R(42));
	P(c, d, e, a, b, R(43));
	P(b, c, d, e, a, R(44));
	P(a, b, c, d, e, R(45));
	P(e, a, b, c, d, R(46));
	P(d, e, a, b, c, R(47));
	P(c, d, e, a, b, R(48));
	P(b, c, d, e, a, R(49));
	P(a, b, c, d, e, R(50));
	P(e, a, b, c, d, R(51));
	P(d, e, a, b, c, R(52));
	P(c, d, e, a, b, R(53));
	P(b, c, d, e, a, R(54));
	P(a, b, c, d, e, R(55));
	P(e, a, b, c, d, R(56));
	P(d, e, a, b, c, R(57));
	P(c, d, e, a, b, R(58));
	P(b, c, d, e, a, R(59));

	#undef K
	#undef F

	#define F(x, y, z) ((x) ^ (y) ^ (z))
	#define K 0xCA62C1D6

	P(a, b, c, d, e, R(60));
	P(e, a, b, c, d, R(61));
	P(d, e, a, b, c, R(62));
	P(c, d, e, a, b, R(63));
	P(b, c, d, e, a, R(64));
	P(a, b, c, d, e, R(65));
	P(e, a, b, c, d, R(66));
	P(d, e, a, b, c, R(67));
	P(c, d, e, a, b, R(68));
	P(b, c, d, e, a, R(69));
	P(a, b, c, d, e, R(70));
	P(e, a, b, c, d, R(71));
	P(d, e, a, b, c, R(72));
	P(c, d, e, a, b, R(73));
	P(b, c, d, e, a, R(74));
	P(a, b, c, d, e, R(75));
	P(e, a, b, c, d, R(76));
	P(d, e, a, b, c, R(77));
	P(c, d, e, a, b, R(78));
	P(b, c, d, e, a, R(79));

#undef K
#undef F

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void sha1_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length) {
	const uint8_t* src = input;
	uint32_t size = length;

	uint32_t left = ctx->total[0] & 0x3F;
	const uint32_t fill = SHA1_BLOCK_SIZE - left;

	ctx->total[0] += size;
	ctx->total[0] &= 0xFFFFFFFF;

	if (ctx->total[0] < size)
		ctx->total[1]++;

	if (left != 0 && size >= fill) {
		memcpy(ctx->buffer + left, src, fill);
		sha1_transform(ctx, ctx->buffer);
		src += fill;
		size -= fill;
		left = 0;
	}

	while (size >= SHA1_BLOCK_SIZE) {
		sha1_transform(ctx, src);
		src += SHA1_BLOCK_SIZE;
		size -= SHA1_BLOCK_SIZE;
	}

	if (size != 0)
		memcpy(ctx->buffer + left, src, size);
}

void sha1_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]) {
	const uint32_t high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
	const uint32_t low = (ctx->total[0] << 3);

	uint8_t msg_length[8];
	PUT_UINT32_BE(high, msg_length, 0);
	PUT_UINT32_BE(low, msg_length, 4);

	const uint32_t last = ctx->total[0] & 0x3F;
	const uint32_t padn = (last < 56) ? (56 - last) : (120 - last);

	sha1_update(ctx, sha1_padding, padn);
	sha1_update(ctx, msg_length, 8);

	PUT_UINT32_BE(ctx->state[0], output, 0);
	PUT_UINT32_BE(ctx->state[1], output, 4);
	PUT_UINT32_BE(ctx->state[2], output, 8);
	PUT_UINT32_BE(ctx->state[3], output, 12);
	PUT_UINT32_BE(ctx->state[4], output, 16);
}

void sha1(const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length) {
	struct sha1_context_t ctx;

	sha1_starts(&ctx);
	sha1_update(&ctx, input, length);
	sha1_finish(&ctx, output);
}

void sha1_hmac_starts(struct sha1_context_t* const ctx, const uint8_t* const key, const uint32_t key_size) {
	uint8_t sum[SHA1_HASH_SIZE];

	const uint8_t* new_key = key;
	uint32_t new_key_size = key_size;

	int i;

	if (new_key_size > SHA1_BLOCK_SIZE) {
		sha1(key, sum, new_key_size);
		new_key = sum;
		new_key_size = SHA1_HASH_SIZE;
	}

	memset(ctx->ipad, 0x36, SHA1_BLOCK_SIZE);
	memset(ctx->opad, 0x5C, SHA1_BLOCK_SIZE);

	for (i = 0; i < new_key_size; ++i) {
		ctx->ipad[i] = ctx->ipad[i] ^ new_key[i];
		ctx->opad[i] = ctx->opad[i] ^ new_key[i];
	}

	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, SHA1_BLOCK_SIZE);
}

void sha1_hmac_update(struct sha1_context_t* const ctx, const uint8_t* const input, const uint32_t length) {
	sha1_update(ctx, input, length);
}

void sha1_hmac_finish(struct sha1_context_t* const ctx, uint8_t output[SHA1_HASH_SIZE]) {
	uint8_t temp[SHA1_HASH_SIZE];

	sha1_finish(ctx, temp);
	sha1_starts(ctx);
	sha1_update(ctx, ctx->opad, SHA1_BLOCK_SIZE);
	sha1_update(ctx, temp, SHA1_HASH_SIZE);
	sha1_finish(ctx, output);
}

void sha1_hmac_reset(struct sha1_context_t* const ctx) {
	sha1_starts(ctx);
	sha1_update(ctx, ctx->ipad, SHA1_BLOCK_SIZE);
}

void sha1_hmac(const uint8_t* const key, const uint32_t key_size, const uint8_t* const input, uint8_t output[SHA1_HASH_SIZE], const uint32_t length) {
	struct sha1_context_t ctx;

	sha1_hmac_starts(&ctx, key, key_size);
	sha1_hmac_update(&ctx, input, length);
	sha1_hmac_finish(&ctx, output);
}

//-----------------------------------------------------------------------------
// Random numbers generation
//-----------------------------------------------------------------------------

static uint32_t xor_shift(void) {
	static uint32_t x = 123456789;
	static uint32_t y = 362436069;
	static uint32_t z = 521288629;
	static uint32_t w = 88675123;

	uint32_t t;
	t = x ^ (x << 11);
	x = y; y = z; z = w;
	w = w ^ (w >> 19) ^ t ^ (t >> 8);

	return w;
}

int generate_random_bytes(uint8_t* const data, const uint32_t length) {
	uint8_t* ptr = data;
	uint32_t rnd;
	uint32_t i;

	for (i = 0; i < length; ++i) {
		rnd = xor_shift() & 0xFF;
		*ptr++ = rnd;
	}

	return 0;
}

//-----------------------------------------------------------------------------
// DES
//-----------------------------------------------------------------------------

/*
 * Expanded DES S-boxes
 */
static const uint32_t SB1[64] =
{
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
};

static const uint32_t SB2[64] =
{
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
};

static const uint32_t SB3[64] =
{
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
};

static const uint32_t SB4[64] =
{
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
};

static const uint32_t SB5[64] =
{
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
};

static const uint32_t SB6[64] =
{
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
};

static const uint32_t SB7[64] =
{
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
};

static const uint32_t SB8[64] =
{
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
};

/*
 * PC1: left and right halves bit-swap
 */
static const uint32_t LHs[16] =
{
    0x00000000, 0x00000001, 0x00000100, 0x00000101,
    0x00010000, 0x00010001, 0x00010100, 0x00010101,
    0x01000000, 0x01000001, 0x01000100, 0x01000101,
    0x01010000, 0x01010001, 0x01010100, 0x01010101
};

static const uint32_t RHs[16] =
{
    0x00000000, 0x01000000, 0x00010000, 0x01010000,
    0x00000100, 0x01000100, 0x00010100, 0x01010100,
    0x00000001, 0x01000001, 0x00010001, 0x01010001,
    0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/*
 * Initial Permutation macro
 */
#define DES_IP(X,Y)                                             \
{                                                               \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; Y ^= T; X ^= T;                   \
    X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF;                    \
}

/*
 * Final Permutation macro
 */
#define DES_FP(X,Y)                                             \
{                                                               \
    X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF;                    \
    T = (X ^ Y) & 0xAAAAAAAA; X ^= T; Y ^= T;                   \
    Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF;                    \
    T = ((Y >>  8) ^ X) & 0x00FF00FF; X ^= T; Y ^= (T <<  8);   \
    T = ((Y >>  2) ^ X) & 0x33333333; X ^= T; Y ^= (T <<  2);   \
    T = ((X >> 16) ^ Y) & 0x0000FFFF; Y ^= T; X ^= (T << 16);   \
    T = ((X >>  4) ^ Y) & 0x0F0F0F0F; Y ^= T; X ^= (T <<  4);   \
}

/*
 * DES round macro
 */
#define DES_ROUND(X,Y)                          \
{                                               \
    T = *SK++ ^ X;                              \
    Y ^= SB8[ (T      ) & 0x3F ] ^              \
         SB6[ (T >>  8) & 0x3F ] ^              \
         SB4[ (T >> 16) & 0x3F ] ^              \
         SB2[ (T >> 24) & 0x3F ];               \
                                                \
    T = *SK++ ^ ((X << 28) | (X >> 4));         \
    Y ^= SB7[ (T      ) & 0x3F ] ^              \
         SB5[ (T >>  8) & 0x3F ] ^              \
         SB3[ (T >> 16) & 0x3F ] ^              \
         SB1[ (T >> 24) & 0x3F ];               \
}

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }

static const unsigned char odd_parity_table[128] = { 1,  2,  4,  7,  8,
        11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31, 32, 35, 37, 38, 41, 42, 44,
        47, 49, 50, 52, 55, 56, 59, 61, 62, 64, 67, 69, 70, 73, 74, 76, 79, 81,
        82, 84, 87, 88, 91, 93, 94, 97, 98, 100, 103, 104, 107, 109, 110, 112,
        115, 117, 118, 121, 122, 124, 127, 128, 131, 133, 134, 137, 138, 140,
        143, 145, 146, 148, 151, 152, 155, 157, 158, 161, 162, 164, 167, 168,
        171, 173, 174, 176, 179, 181, 182, 185, 186, 188, 191, 193, 194, 196,
        199, 200, 203, 205, 206, 208, 211, 213, 214, 217, 218, 220, 223, 224,
        227, 229, 230, 233, 234, 236, 239, 241, 242, 244, 247, 248, 251, 253,
        254 };

void des_key_set_parity( unsigned char key[DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < DES_KEY_SIZE; i++ )
        key[i] = odd_parity_table[key[i] / 2];
}

/*
 * Check the given key's parity, returns 1 on failure, 0 on SUCCESS
 */
int des_key_check_key_parity( const unsigned char key[DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < DES_KEY_SIZE; i++ )
        if ( key[i] != odd_parity_table[key[i] / 2] )
            return( 1 );

    return( 0 );
}

/*
 * Table of weak and semi-weak keys
 *
 * Source: http://en.wikipedia.org/wiki/Weak_key
 *
 * Weak:
 * Alternating ones + zeros (0x0101010101010101)
 * Alternating 'F' + 'E' (0xFEFEFEFEFEFEFEFE)
 * '0xE0E0E0E0F1F1F1F1'
 * '0x1F1F1F1F0E0E0E0E'
 *
 * Semi-weak:
 * 0x011F011F010E010E and 0x1F011F010E010E01
 * 0x01E001E001F101F1 and 0xE001E001F101F101
 * 0x01FE01FE01FE01FE and 0xFE01FE01FE01FE01
 * 0x1FE01FE00EF10EF1 and 0xE01FE01FF10EF10E
 * 0x1FFE1FFE0EFE0EFE and 0xFE1FFE1FFE0EFE0E
 * 0xE0FEE0FEF1FEF1FE and 0xFEE0FEE0FEF1FEF1
 *
 */

#define WEAK_KEY_COUNT 16

static const unsigned char weak_key_table[WEAK_KEY_COUNT][DES_KEY_SIZE] =
{
    { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
    { 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E },
    { 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 },

    { 0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E },
    { 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01 },
    { 0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1 },
    { 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01 },
    { 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE },
    { 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01 },
    { 0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1 },
    { 0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E },
    { 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE },
    { 0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E },
    { 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE },
    { 0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1 }
};

int des_key_check_weak( const unsigned char key[DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < WEAK_KEY_COUNT; i++ )
        if( memcmp( weak_key_table[i], key, DES_KEY_SIZE) == 0)
            return( 1 );

    return( 0 );
}

static void des_setkey( uint32_t SK[32], const unsigned char key[DES_KEY_SIZE] )
{
    int i;
    uint32_t X, Y, T;

    GET_UINT32_BE( X, key, 0 );
    GET_UINT32_BE( Y, key, 4 );

    /*
     * Permuted Choice 1
     */
    T =  ((Y >>  4) ^ X) & 0x0F0F0F0F;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0x10101010;  X ^= T; Y ^= (T      );

    X =   (LHs[ (X      ) & 0xF] << 3) | (LHs[ (X >>  8) & 0xF ] << 2)
        | (LHs[ (X >> 16) & 0xF] << 1) | (LHs[ (X >> 24) & 0xF ]     )
        | (LHs[ (X >>  5) & 0xF] << 7) | (LHs[ (X >> 13) & 0xF ] << 6)
        | (LHs[ (X >> 21) & 0xF] << 5) | (LHs[ (X >> 29) & 0xF ] << 4);

    Y =   (RHs[ (Y >>  1) & 0xF] << 3) | (RHs[ (Y >>  9) & 0xF ] << 2)
        | (RHs[ (Y >> 17) & 0xF] << 1) | (RHs[ (Y >> 25) & 0xF ]     )
        | (RHs[ (Y >>  4) & 0xF] << 7) | (RHs[ (Y >> 12) & 0xF ] << 6)
        | (RHs[ (Y >> 20) & 0xF] << 5) | (RHs[ (Y >> 28) & 0xF ] << 4);

    X &= 0x0FFFFFFF;
    Y &= 0x0FFFFFFF;

    /*
     * calculate subkeys
     */
    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0x0FFFFFFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0x0FFFFFFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0x0FFFFFFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0x0FFFFFFF;
        }

        *SK++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
                | ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
                | ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
                | ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
                | ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
                | ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
                | ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
                | ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
                | ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
                | ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
                | ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        *SK++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
                | ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
                | ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
                | ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
                | ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
                | ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
                | ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
                | ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
                | ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
                | ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
                | ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }
}

/*
 * DES key schedule (56-bit, encryption)
 */
int des_setkey_enc( des_context *ctx, const unsigned char key[DES_KEY_SIZE] )
{
    des_setkey( ctx->sk, key );

    return( 0 );
}

/*
 * DES key schedule (56-bit, decryption)
 */
int des_setkey_dec( des_context *ctx, const unsigned char key[DES_KEY_SIZE] )
{
    int i;

    des_setkey( ctx->sk, key );

    for( i = 0; i < 16; i += 2 )
    {
        SWAP( ctx->sk[i    ], ctx->sk[30 - i] );
        SWAP( ctx->sk[i + 1], ctx->sk[31 - i] );
    }

    return( 0 );
}

static void des3_set2key( uint32_t esk[96],
                          uint32_t dsk[96],
                          const unsigned char key[DES_KEY_SIZE*2] )
{
    int i;

    des_setkey( esk, key );
    des_setkey( dsk + 32, key + 8 );

    for( i = 0; i < 32; i += 2 )
    {
        dsk[i     ] = esk[30 - i];
        dsk[i +  1] = esk[31 - i];

        esk[i + 32] = dsk[62 - i];
        esk[i + 33] = dsk[63 - i];

        esk[i + 64] = esk[i    ];
        esk[i + 65] = esk[i + 1];

        dsk[i + 64] = dsk[i    ];
        dsk[i + 65] = dsk[i + 1];
    }
}

/*
 * Triple-DES key schedule (112-bit, encryption)
 */
int des3_set2key_enc( des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 2] )
{
    uint32_t sk[96];

    des3_set2key( ctx->sk, sk, key );
    memset( sk,  0, sizeof( sk ) );

    return( 0 );
}

/*
 * Triple-DES key schedule (112-bit, decryption)
 */
int des3_set2key_dec( des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 2] )
{
    uint32_t sk[96];

    des3_set2key( sk, ctx->sk, key );
    memset( sk,  0, sizeof( sk ) );

    return( 0 );
}

static void des3_set3key( uint32_t esk[96],
                          uint32_t dsk[96],
                          const unsigned char key[24] )
{
    int i;

    des_setkey( esk, key );
    des_setkey( dsk + 32, key +  8 );
    des_setkey( esk + 64, key + 16 );

    for( i = 0; i < 32; i += 2 )
    {
        dsk[i     ] = esk[94 - i];
        dsk[i +  1] = esk[95 - i];

        esk[i + 32] = dsk[62 - i];
        esk[i + 33] = dsk[63 - i];

        dsk[i + 64] = esk[30 - i];
        dsk[i + 65] = esk[31 - i];
    }
}

/*
 * Triple-DES key schedule (168-bit, encryption)
 */
int des3_set3key_enc( des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 3] )
{
    uint32_t sk[96];

    des3_set3key( ctx->sk, sk, key );
    memset( sk, 0, sizeof( sk ) );

    return( 0 );
}

/*
 * Triple-DES key schedule (168-bit, decryption)
 */
int des3_set3key_dec( des3_context *ctx, const unsigned char key[DES_KEY_SIZE * 3] )
{
    uint32_t sk[96];

    des3_set3key( sk, ctx->sk, key );
    memset( sk, 0, sizeof( sk ) );

    return( 0 );
}

/*
 * DES-ECB block encryption/decryption
 */
int des_crypt_ecb( des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}

/*
 * DES-CBC buffer encryption/decryption
 */
int des_crypt_cbc( des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( POLARSSL_ERR_DES_INVALID_INPUT_LENGTH );

    if( mode == DES_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            des_crypt_ecb( ctx, output, output );
            memcpy( iv, output, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else /* DES_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
            des_crypt_ecb( ctx, input, output );

            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}

/*
 * 3DES-ECB block encryption/decryption
 */
int des3_crypt_ecb( des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( X, Y );
        DES_ROUND( Y, X );
    }

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}

/*
 * 3DES-CBC buffer encryption/decryption
 */
int des3_crypt_cbc( des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( POLARSSL_ERR_DES_INVALID_INPUT_LENGTH );

    if( mode == DES_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            des3_crypt_ecb( ctx, output, output );
            memcpy( iv, output, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else /* DES_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
            des3_crypt_ecb( ctx, input, output );

            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}

int des3_encrypt_cbc(const unsigned char key[DES_KEY_SIZE * 2], unsigned char iv[8], const unsigned char *input, unsigned char *output, size_t length)
{
	int result;

	des3_context ctx;

	uint8_t temp[8];

	result = des3_set2key_enc( &ctx, key );
	if (result != 0)
		return result;

	memcpy(temp, iv, 8);

	result =  des3_crypt_cbc( &ctx, DES_ENCRYPT, length, temp, input, output );
	if (result != 0)
		return result;

	return 0;
}

int des3_decrypt_cbc(const unsigned char key[DES_KEY_SIZE * 2], unsigned char iv[8], const unsigned char *input, unsigned char *output, size_t length)
{
	int result;

	des3_context ctx;

	uint8_t temp[8];

	result = des3_set2key_dec( &ctx, key );
	if (result != 0)
		return result;

	memcpy(temp, iv, 8);

	result =  des3_crypt_cbc( &ctx, DES_DECRYPT, length, temp, input, output );
	if (result != 0)
		return result;

	return 0;
}