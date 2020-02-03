/*
 * ndpi_content_match.c
 *
 * Copyright (C) 2011-19 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#define TLD "(?i)(?:\\.co(?:m)?)?\\.[a-z]{2,63}$"
/* ****************************************************** */

static ndpi_network host_protocol_list[] = {
  /*
   
    Facebook, Inc.
    origin AS32934, AS54115
  */

  { 0x1F0D1800 /* 31.13.24.0/21 */, 21, NDPI_PROTOCOL_FACEBOOK },
  { 0x1F0D4000 /* 31.13.64.0/18 */, 18, NDPI_PROTOCOL_FACEBOOK },
  { 0x2D402800 /* 45.64.40.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0x42DC9000 /* 66.220.144.0/20 */, 20, NDPI_PROTOCOL_FACEBOOK },
  { 0x453FB000 /* 69.63.176.0/20 */, 20, NDPI_PROTOCOL_FACEBOOK },
  { 0x45ABE000 /* 69.171.224.0/19 */, 19, NDPI_PROTOCOL_FACEBOOK },
  { 0x4A774C00 /* 74.119.76.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0x67046000 /* 103.4.96.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0x81860000 /* 129.134.0.0/16 */, 16, NDPI_PROTOCOL_FACEBOOK },
  { 0x9DF00000 /* 157.240.0.0/16 */, 16, NDPI_PROTOCOL_FACEBOOK },
  { 0xADFC4000 /* 173.252.64.0/18 */, 18, NDPI_PROTOCOL_FACEBOOK },
  { 0xB33CC000 /* 179.60.192.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0xB93CD800 /* 185.60.216.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0xC7C94000 /* 199.201.64.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },
  { 0xCC0F1400 /* 204.15.20.0/22 */, 22, NDPI_PROTOCOL_FACEBOOK },

  

  /*
    WhatsApp Inc.
    List of the WhatsApp server IP addresses and ranges (https://developers.facebook.com/docs/whatsapp/network-debugging/ Dec 21, 2018)
  */
  { 0x6CA8AE00 /* 108.168.174.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8B0C0 /* 108.168.176.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8B100 /* 108.168.177.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8B460 /* 108.168.180.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8FE41 /* 108.168.254.65/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8FFE0 /* 108.168.255.224/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x6CA8FFE3 /* 108.168.255.227/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00135 /* 157.240.1.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00136 /* 157.240.1.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00A35 /* 157.240.10.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00A36 /* 157.240.10.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00B35 /* 157.240.11.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00B36 /* 157.240.11.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00C35 /* 157.240.12.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00C36 /* 157.240.12.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00D36 /* 157.240.13.54/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00E34 /* 157.240.14.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00F35 /* 157.240.15.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00F36 /* 157.240.15.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01034 /* 157.240.16.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01234 /* 157.240.18.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01335 /* 157.240.19.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01336 /* 157.240.19.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00235 /* 157.240.2.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00236 /* 157.240.2.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01434 /* 157.240.20.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01534 /* 157.240.21.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01635 /* 157.240.22.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01636 /* 157.240.22.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01735 /* 157.240.23.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01736 /* 157.240.23.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01D35 /* 157.240.29.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01D36 /* 157.240.29.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00635 /* 157.240.6.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00636 /* 157.240.6.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00735 /* 157.240.7.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00736 /* 157.240.7.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00835 /* 157.240.8.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00836 /* 157.240.8.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00935 /* 157.240.9.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00936 /* 157.240.9.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E550060 /* 158.85.0.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E55E0A0 /* 158.85.224.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E55E920 /* 158.85.233.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E55F980 /* 158.85.249.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E55FE40 /* 158.85.254.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E552E80 /* 158.85.46.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E5530E0 /* 158.85.48.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E5505C0 /* 158.85.5.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E553A00 /* 158.85.58.0/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0x9E553DC0 /* 158.85.61.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92CA700 /* 169.44.167.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C2400 /* 169.44.36.0/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C3940 /* 169.44.57.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C3A40 /* 169.44.58.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5000 /* 169.44.80.0/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5280 /* 169.44.82.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C52C0 /* 169.44.82.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5260 /* 169.44.82.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5300 /* 169.44.83.0/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5380 /* 169.44.83.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C53C0 /* 169.44.83.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5360 /* 169.44.83.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5400 /* 169.44.84.0/24 */, 24, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C5540 /* 169.44.85.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92C57A0 /* 169.44.87.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DA9C0 /* 169.45.169.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DB660 /* 169.45.182.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DD240 /* 169.45.210.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DD6E0 /* 169.45.214.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DDBE0 /* 169.45.219.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DEDC0 /* 169.45.237.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DEE20 /* 169.45.238.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DF2C0 /* 169.45.242.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DF8A0 /* 169.45.248.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92DF860 /* 169.45.248.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92D4720 /* 169.45.71.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92D4760 /* 169.45.71.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92D5780 /* 169.45.87.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92E6F90 /* 169.46.111.144/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92E34E0 /* 169.46.52.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F8260 /* 169.47.130.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F9100 /* 169.47.145.0/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F9980 /* 169.47.153.128/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92FC0C0 /* 169.47.192.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92FC280 /* 169.47.194.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92FC680 /* 169.47.198.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92FD4A0 /* 169.47.212.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2180 /* 169.47.33.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2320 /* 169.47.35.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2580 /* 169.47.37.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2880 /* 169.47.40.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2AA0 /* 169.47.42.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2AC0 /* 169.47.42.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2A60 /* 169.47.42.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F2FA0 /* 169.47.47.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F05C0 /* 169.47.5.192/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA92F0640 /* 169.47.6.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9307220 /* 169.48.114.32/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93079C0 /* 169.48.121.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9307A40 /* 169.48.122.64/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA930D2B0 /* 169.48.210.176/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA930D2E0 /* 169.48.210.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA930D340 /* 169.48.211.64/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA930D480 /* 169.48.212.128/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA935FA80 /* 169.53.250.128/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA935FC40 /* 169.53.252.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA935FF40 /* 169.53.255.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9351D80 /* 169.53.29.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9353020 /* 169.53.48.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93547E0 /* 169.53.71.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9355140 /* 169.53.81.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA936C1A0 /* 169.54.193.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93602A0 /* 169.54.2.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA936D200 /* 169.54.210.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA936DE80 /* 169.54.222.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9362CE0 /* 169.54.44.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9363320 /* 169.54.51.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93637C0 /* 169.54.55.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93764A0 /* 169.55.100.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9377E40 /* 169.55.126.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA937D260 /* 169.55.210.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA937EBA0 /* 169.55.235.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9373C94 /* 169.55.60.148/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9373CAA /* 169.55.60.170/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93743E0 /* 169.55.67.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9374580 /* 169.55.69.128/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9374A20 /* 169.55.74.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA9374B60 /* 169.55.75.96/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C8180 /* 169.60.129.128/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C9300 /* 169.60.147.0/24 */, 24, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93CC540 /* 169.60.197.64/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C4A70 /* 169.60.74.112/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C4A80 /* 169.60.74.128/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C4A20 /* 169.60.74.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C4B80 /* 169.60.75.128/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93C4F00 /* 169.60.79.0/24 */, 24, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93D6500 /* 169.61.101.0/24 */, 24, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93D5190 /* 169.61.81.144/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93D51E0 /* 169.61.81.224/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93D5240 /* 169.61.82.64/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93D5480 /* 169.61.84.128/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93F4080 /* 169.63.64.128/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93F4920 /* 169.63.73.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93F4940 /* 169.63.73.64/26 */, 26, NDPI_PROTOCOL_WHATSAPP },
  { 0xA93F4C00 /* 169.63.76.0/25 */, 25, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC0A220 /* 173.192.162.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC0DB80 /* 173.192.219.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC0DEA0 /* 173.192.222.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC1E680 /* 173.193.230.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC1E6C0 /* 173.193.230.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xADC1EF00 /* 173.193.239.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xAE24D080 /* 174.36.208.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xAE24D220 /* 174.36.210.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xAE24FBC0 /* 174.36.251.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xAE25F340 /* 174.37.243.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xAE25FB00 /* 174.37.251.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC030 /* 179.60.192.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC031 /* 179.60.192.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC033 /* 179.60.192.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC134 /* 179.60.193.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC235 /* 179.60.194.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC236 /* 179.60.194.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC331 /* 179.60.195.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC333 /* 179.60.195.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB8AD8840 /* 184.173.136.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xB8AD9320 /* 184.173.147.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xB8ADA140 /* 184.173.161.64/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB8ADAD74 /* 184.173.173.116/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB8ADB320 /* 184.173.179.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CD835 /* 185.60.216.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CD836 /* 185.60.216.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CD935 /* 185.60.217.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CD936 /* 185.60.217.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CDA35 /* 185.60.218.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CDA36 /* 185.60.218.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CDB35 /* 185.60.219.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB93CDB36 /* 185.60.219.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xC09BD4C0 /* 192.155.212.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xC60BC1B6 /* 198.11.193.182/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0xC60BFB20 /* 198.11.251.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xC6175000 /* 198.23.80.0/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xD02B73C0 /* 208.43.115.192/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0xD02B754F /* 208.43.117.79/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xD02B7A80 /* 208.43.122.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4033 /* 31.13.64.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4035 /* 31.13.64.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4131 /* 31.13.65.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4132 /* 31.13.65.50/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4334 /* 31.13.67.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4430 /* 31.13.68.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4434 /* 31.13.68.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D45F0 /* 31.13.69.240/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4631 /* 31.13.70.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4632 /* 31.13.70.50/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4731 /* 31.13.71.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4732 /* 31.13.71.50/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4830 /* 31.13.72.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4834 /* 31.13.72.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4934 /* 31.13.73.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4A34 /* 31.13.74.52/31 */, 31, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4B30 /* 31.13.75.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4B34 /* 31.13.75.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4C51 /* 31.13.76.81/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4C52 /* 31.13.76.82/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4E35 /* 31.13.78.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4E37 /* 31.13.78.55/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5030 /* 31.13.80.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5035 /* 31.13.80.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5130 /* 31.13.81.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5135 /* 31.13.81.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5233 /* 31.13.82.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5237 /* 31.13.82.55/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5331 /* 31.13.83.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5333 /* 31.13.83.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5431 /* 31.13.84.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5433 /* 31.13.84.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5531 /* 31.13.85.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5533 /* 31.13.85.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5631 /* 31.13.86.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5633 /* 31.13.86.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5730 /* 31.13.87.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5733 /* 31.13.87.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5831 /* 31.13.88.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5834 /* 31.13.88.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5935 /* 31.13.89.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5936 /* 31.13.89.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5A31 /* 31.13.90.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5A33 /* 31.13.90.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5B31 /* 31.13.91.49/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5B33 /* 31.13.91.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5C30 /* 31.13.92.48/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5C34 /* 31.13.92.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5D35 /* 31.13.93.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5D36 /* 31.13.93.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5E34 /* 31.13.94.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5E36 /* 31.13.94.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5F32 /* 31.13.95.50/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D5F3F /* 31.13.95.63/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216C6CC /* 50.22.198.204/30 */, 30, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216D280 /* 50.22.210.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216D220 /* 50.22.210.32/30 */, 30, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216E140 /* 50.22.225.64/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216EBF8 /* 50.22.235.248/30 */, 30, NDPI_PROTOCOL_WHATSAPP },
  { 0x3216F0A0 /* 50.22.240.160/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x32175A80 /* 50.23.90.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x32613980 /* 50.97.57.128/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E0C70 /* 75.126.12.112/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E7B40 /* 75.126.123.64/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E8AA0 /* 75.126.138.160/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E8D50 /* 75.126.141.80/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E1430 /* 75.126.20.48/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E2720 /* 75.126.39.32/27 */, 27, NDPI_PROTOCOL_WHATSAPP },
  { 0x4B7E51C0 /* 75.126.81.192/28 */, 28, NDPI_PROTOCOL_WHATSAPP },
  { 0x66846036 /* 102.132.96.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x66846136 /* 102.132.97.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00D36 /* 157.240.13.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00E34 /* 157.240.14.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01034 /* 157.240.16.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01234 /* 157.240.18.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF0C034 /* 157.240.192.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF0C132 /* 157.240.193.50/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF0C236 /* 157.240.194.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01434 /* 157.240.20.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01533 /* 157.240.21.51/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01534 /* 157.240.21.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01836 /* 157.240.24.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01936 /* 157.240.25.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01A36 /* 157.240.26.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01B36 /* 157.240.27.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF00336 /* 157.240.3.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x9DF01E36 /* 157.240.30.54/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0xB33CC134 /* 179.60.193.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4238 /* 31.13.66.56/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4334 /* 31.13.67.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4934 /* 31.13.73.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4A34 /* 31.13.74.52/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  { 0x1F0D4F35 /* 31.13.79.53/32 */, 32, NDPI_PROTOCOL_WHATSAPP },
  /*
    OpenDNS, LLC
    origin AS36692, AS30607
  */
  { 0x26631400 /* 38.99.20.0/23 */, 23, NDPI_PROTOCOL_OPENDNS },
  { 0x3F504FC0 /* 63.80.79.192/26 */, 26, NDPI_PROTOCOL_OPENDNS },
  { 0x43D74000 /* 67.215.64.0/19 */, 19, NDPI_PROTOCOL_OPENDNS },
  { 0x92700000 /* 146.112.0.0/16 */, 16, NDPI_PROTOCOL_OPENDNS },
  { 0xB93C5400 /* 185.60.84.0/24 */, 24, NDPI_PROTOCOL_OPENDNS },
  { 0xB93C5500 /* 185.60.85.0/24 */, 24, NDPI_PROTOCOL_OPENDNS },
  { 0xB93C5600 /* 185.60.86.0/24 */, 24, NDPI_PROTOCOL_OPENDNS },
  { 0xB93C5700 /* 185.60.87.0/24 */, 24, NDPI_PROTOCOL_OPENDNS },
  { 0xCCC2E800 /* 204.194.232.0/21 */, 21, NDPI_PROTOCOL_OPENDNS },
  { 0xD043D800 /* 208.67.216.0/21 */, 21, NDPI_PROTOCOL_OPENDNS },
  { 0xD0452000 /* 208.69.32.0/21 */, 21, NDPI_PROTOCOL_OPENDNS },
  /*
    GitHub, Inc.
    origin AS36459
  */
  { 0xC01EFC00 /* 192.30.252.0/22 */, 22, NDPI_PROTOCOL_GITHUB },
   /* End */
  { 0x0, 0, 0 }
};


/* ****************************************************** */

static ndpi_protocol_match host_match[] = {
  
  { "facebook.com", NULL, "facebook" TLD,                         "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "fbstatic-a.akamaihd.net", NULL, "fbstatic-a\\.akamaihd" TLD, "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".fbcdn.net", NULL, "\\.fbcdn" TLD,                           "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { "fbcdn-", NULL, "fbcdn-",                                     "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".facebook.net", NULL, "\\.facebook" TLD,                     "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },
  { ".fbsbx.com", NULL, "\\.fbsbx" TLD,                           "Facebook",         NDPI_PROTOCOL_FACEBOOK, NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK, NDPI_PROTOCOL_FUN },

  
  

    
  
{ "mmg-fna.whatsapp.net", NULL, "mmg-fna\\.whatsapp" TLD,            "WhatsAppFiles",    NDPI_PROTOCOL_WHATSAPP_FILES, NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT, NDPI_PROTOCOL_ACCEPTABLE },
  { ".whatsapp.", NULL, "\\.whatsapp" TLD,                             "WhatsApp",         NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "g.whatsapp.net", NULL, "g\\.whatsapp" TLD,                        "WhatsApp",         NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "v.whatsapp.net", NULL, "v\\.whatsapp" TLD,                        "WhatsApp",         NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "mmg.whatsapp.net", NULL, "mmg\\.whatsapp" TLD,                    "WhatsApp",         NDPI_PROTOCOL_WHATSAPP, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },

  
  { "edge-mqtt.facebook.com", NULL, "edge-mqtt\\.facebook" TLD,        "Messenger",        NDPI_PROTOCOL_MESSENGER, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },
  { "mqtt-mini.facebook.com", NULL, "mqtt-mini\\.facebook" TLD,        "Messenger",        NDPI_PROTOCOL_MESSENGER, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE }, /* Messenger Lite */
  { "messenger.com", NULL, "messenger\\.com" TLD,                      "Messenger",        NDPI_PROTOCOL_MESSENGER, NDPI_PROTOCOL_CATEGORY_CHAT, NDPI_PROTOCOL_ACCEPTABLE },



 

  { "d295hzzivaok4k.cloudfront.net", NULL, "d295hzzivaok4k\\.cloudfront" TLD,"OpenDNS",      NDPI_PROTOCOL_OPENDNS, NDPI_PROTOCOL_CATEGORY_WEB, NDPI_PROTOCOL_ACCEPTABLE },
  { ".opendns.com", NULL, "\\.opendns" TLD,                                  "OpenDNS",      NDPI_PROTOCOL_OPENDNS, NDPI_PROTOCOL_CATEGORY_NETWORK, NDPI_PROTOCOL_ACCEPTABLE },

  
  /* Detected "slack-assets2.s3-us-west-2.amazonaws.com.". Omitted "*amazonaws.com" CDN, but no generic pattern to use on first part */
  { "github.com", NULL, "github" TLD,                                  "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".github.com", NULL, "\\.github" TLD,                              "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "github.io", NULL, NULL,                                           "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".github.io", NULL, NULL,                                          "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { "githubusercontent.com", NULL, "githubusercontent" TLD,            "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".githubusercontent.com", NULL, "\\.githubusercontent" TLD,        "Github",           NDPI_PROTOCOL_GITHUB, NDPI_PROTOCOL_CATEGORY_COLLABORATIVE, NDPI_PROTOCOL_ACCEPTABLE },

  


  { NULL, NULL, NULL, 0 }
};

/* ******************************************************************** */

static ndpi_category_match category_match[] = {
   { ".edgecastcdn.net", "egdecastcdn" TLD,                       NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".hwcdn.net", "hwcdn" TLD,                                   NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".llnwd.net", "llnwd" TLD,                                   NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".llns.net", "llns" TLD,                                     NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".fastly.net", "fastly" TLD,                                 NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".akamaiedge.net", "akamaiedge" TLD,                         NDPI_PROTOCOL_CATEGORY_MEDIA },
   { ".vultr.com", "vultr" TLD,                                   NDPI_PROTOCOL_CATEGORY_CLOUD },
   { "baidu.com", "baidu" TLD,                                    NDPI_PROTOCOL_CATEGORY_WEB },
   { "icq.com", "icq" TLD,                                        NDPI_PROTOCOL_CATEGORY_CHAT },
   { "quickplay.com", "quickplay" TLD,                            NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".iqiyi.com", "\\.iqiyi" TLD,                                NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".qiyi.com", "\\.qiyi" TLD,                                  NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".71.am", "\\.71" TLD,                                       NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".qiyipic.com", "\\.qiyipic" TLD,                            NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".1kxun.", "\\.1kxun\\.",                                    NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "tcad.wedolook.com", "tcad\\.wedolook" TLD,                  NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".rapidvideo.com", "\\.rapidvideo" TLD,                      NDPI_PROTOCOL_CATEGORY_STREAMING },
   { ".playercdn.net", "\\.playercdn" TLD,                        NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "showmax.com", "showmax" TLD,                                NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "showmax.akamaized.net", "showmax\\.akamaized" TLD,          NDPI_PROTOCOL_CATEGORY_STREAMING },

   /* Hulu Streaming services AS23286 */
   { "8.28.124.0/24",         NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "8.28.125.0/24",         NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "199.200.50.0/23",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "199.200.51.0/24",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "199.60.116.0/24",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "208.91.158.0/23",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "209.249.186.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },

   /* Disney Streaming services AS11251 */
   { "8.4.4.0/24",            NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "8.5.5.0/24",            NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "8.33.30.0/24",          NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "63.116.222.0/24",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "63.116.223.0/24",       NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.192.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.193.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.200.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.201.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.202.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.203.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.204.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.205.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.206.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.207.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.208.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.209.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.212.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.216.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },
   { "139.104.217.0/24",      NULL,                               NDPI_PROTOCOL_CATEGORY_STREAMING },

   { NULL, NULL, 0 }
};

/* ******************************************************************** */

/*
  Tor
  The tor protocol uses SSL to contact peers so it could be exchanged with
  standard SSL. However the host names such as

  - www.fgd2iwya7vinfutj5wq5we.com
  - www.qbtxzhetq4s2f.com
  - www.fgd2iwya7vinfutj5wq5we.net

  See also DGA (Domain Generation Algorithm)

  In essence www.<name>.com|net

  To do things properly we should check if host name in the certificate
  exists or if the IP address of the SSL peer resolves to a name. Unfortunately
  for performance reasons we can't afford to do a DNS lookup in nDPI (however apps
  can do it if possible) and thus we have created a heuristic algorithm that tries
  to check the host name (in the SSL certificate) to see if it looks like a
  random name or a real name. We cannot use a dictionary (how can the kernel read a file?)
  and this we use bigrams distribution to decide if the string looks like a
  word or just random chars.

  http://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
*/

static const char *ndpi_en_bigrams[] = {
  "aa", "ba", "ca", "da", "ea", "fa", "ga", "ha", "ia", "ja", "ka", "la", "ma", "na", "oa", "pa", "qa",
  "ra", "sa", "ta", "ua", "va", "wa", "xa", "ya", "za", "ab", "bb", "db", "eb", "fb", "gb", "hb", "ib",
  "kb", "lb", "mb", "nb", "ob", "pb", "rb", "sb", "tb", "ub", "wb", "yb", "ac", "bc", "cc", "dc", "ec",
  "fc", "gc", "hc", "ic", "kc", "lc", "mc", "nc", "oc", "pc", "rc", "sc", "tc", "uc", "wc", "xc", "yc",
  "ad", "bd", "cd", "dd", "ed", "fd", "gd", "hd", "id", "kd", "ld", "md", "nd", "od", "pd", "rd", "sd",
  "td", "ud", "wd", "xd", "yd", "zd", "ae", "be", "ce", "de", "ee", "fe", "ge", "he", "ie", "je", "ke",
  "le", "me", "ne", "oe", "pe", "re", "se", "te", "ue", "ve", "we", "xe", "ye", "ze", "af", "bf", "df",
  "ef", "ff", "gf", "hf", "if", "kf", "lf", "mf", "nf", "of", "pf", "rf", "sf", "tf", "uf", "wf", "xf",
  "yf", "zf", "ag", "bg", "dg", "eg", "fg", "gg", "hg", "ig", "kg", "lg", "ng", "og", "pg", "rg", "sg",
  "tg", "ug", "wg", "yg", "ah", "bh", "ch", "dh", "eh", "fh", "gh", "hh", "ih", "kh", "lh", "mh", "nh",
  "oh", "ph", "rh", "sh", "th", "uh", "wh", "xh", "yh", "ai", "bi", "ci", "di", "ei", "fi", "gi", "hi",
  "ii", "ji", "ki", "li", "mi", "ni", "oi", "pi", "qi", "ri", "si", "ti", "ui", "vi", "wi", "xi", "yi",
  "zi", "aj", "bj", "dj", "ej", "fj", "gj", "hj", "ij", "jj", "kj", "lj", "nj", "oj", "pj", "rj", "sj",
  "tj", "uj", "wj", "yj", "ak", "ck", "dk", "ek", "gk", "ik", "kk", "lk", "mk", "nk", "ok", "pk", "rk",
  "sk", "tk", "uk", "wk", "yk", "zk", "al", "bl", "cl", "dl", "el", "fl", "gl", "hl", "il", "kl", "ll",
  "ml", "nl", "ol", "pl", "rl", "sl", "tl", "ul", "vl", "wl", "xl", "yl", "zl", "am", "bm", "cm", "dm",
  "em", "fm", "gm", "hm", "im", "km", "lm", "mm", "nm", "om", "pm", "rm", "sm", "tm", "um", "wm", "xm",
  "ym", "zm", "an", "bn", "cn", "dn", "en", "fn", "gn", "hn", "in", "kn", "ln", "mn", "nn", "on", "pn",
  "rn", "sn", "tn", "un", "wn", "xn", "yn", "ao", "bo", "co", "do", "eo", "fo", "go", "ho", "io", "jo",
  "ko", "lo", "mo", "no", "oo", "po", "ro", "so", "to", "uo", "vo", "wo", "xo", "yo", "zo", "ap", "bp",
  "dp", "ep", "fp", "gp", "hp", "ip", "kp", "lp", "mp", "np", "op", "pp", "rp", "sp", "tp", "up", "wp",
  "xp", "yp", "zp", "aq", "cq", "dq", "eq", "hq", "iq", "nq", "oq", "qq", "rq", "sq", "uq", "xq", "ar",
  "br", "cr", "dr", "er", "fr", "gr", "hr", "ir", "kr", "lr", "mr", "nr", "or", "pr", "rr", "sr", "tr",
  "ur", "vr", "wr", "xr", "yr", "as", "bs", "cs", "ds", "es", "fs", "gs", "hs", "is", "ks", "ls", "ms",
  "ns", "os", "ps", "rs", "ss", "ts", "us", "vs", "ws", "xs", "ys", "at", "bt", "ct", "dt", "et", "ft",
  "gt", "ht", "it", "kt", "lt", "mt", "nt", "ot", "pt", "rt", "st", "tt", "ut", "wt", "xt", "yt", "zt",
  "au", "bu", "cu", "du", "eu", "fu", "gu", "hu", "iu", "ju", "ku", "lu", "mu", "nu", "ou", "pu", "qu",
  "ru", "su", "tu", "uu", "vu", "wu", "xu", "yu", "zu", "av", "bv", "dv", "ev", "iv", "lv", "mv", "nv",
  "ov", "rv", "sv", "tv", "uv", "vv", "zv", "aw", "bw", "dw", "ew", "fw", "gw", "hw", "iw", "kw", "lw",
  "mw", "nw", "ow", "pw", "rw", "sw", "tw", "uw", "ww", "xw", "yw", "zw", "ax", "ex", "ix", "nx", "ox",
  "rx", "ux", "xx", "yx", "ay", "by", "cy", "dy", "ey", "fy", "gy", "hy", "ky", "ly", "my", "ny", "oy",
  "py", "ry", "sy", "ty", "uy", "vy", "wy", "xy", "yy", "zy", "az", "bz", "cz", "dz", "ez", "gz", "iz",
  "lz", "nz", "oz", "pz", "rz", "tz", "uz", "zz",
  NULL };

/* ******************************************************************** */

static const char *ndpi_en_impossible_bigrams[] = {
  "bk", "bq", "bx", "cb", "cf", "cg", "cj", "cp", "cv", "cw", "cx", "dx", "fk", "fq", "fv", "fx", /* "ee", removed it can be found in 'meeting' */
  "fz", "gq", "gv", "gx", "hh", "hk", "hv", "hx", "hz", "iy", "jb", /* "jc", jcrew.com */ "jd", "jf", "jg", "jh", "jk",
  "jl", "jm", "jn", "jp", "jq", "jr", /* "js", */ "jt", "jv", "jw", "jx", "jy", "jz", "kg", "kq", "kv", "kx",
  "kz", "lq", "lx", /* "mg" tamgrt.com , */ "mj", "mq", "mx", "mz", "pq", "pv", "px", "qb", "qc", "qd", "qe", "qf", "ii",
  "qg", "qh", "qj", "qk", "ql", "qm", "qn", "qo", "qp", "qr", "qs", "qt", "qv", "qw", "qx", "qy", "uu",
  "qz", "sx", "sz", "tq", "tx", "vb", "vc", "vd", "vf", "vg", "vh", "vj", "vm", "vn", /* "vp", Removed for vpbank.com */ "bw", /* "vk", "zr" Removed for kavkazr */
  "vq", "vt", "vw", "vx", "vz", "wq", "wv", "wx", "wz", /* "xb", foxbusiness.com */
  	"xg", "xj", "xk", "xv", "xz", "xw", "yd", /*"yp", Removed for paypal */
  "yj", "yq", "yv", "yz", "yw", "zb", "zc", "zg", "zh", "zj", "zn", "zq", "zs", "zx", "wh", "wk",
  "wb", "zk", "kp", "zk", "xy",
  NULL };
