/**/

#include "internal.h"

void adns__procdgram(adns_state ads, const byte *dgram, int len, int serv) {
  /* FIXME do something with incoming datagrams */
  adns__diag(ads,serv,"received datagram size %d",len);

  
}

struct adns__rrtype adns_r_a       [1]= {{  1, rcf_a             }};
struct adns__rrtype adns_r_ns      [1]= {{  2, rcf_ns            }};
struct adns__rrtype adns_r_ns_raw  [1]= {{  2, rcf_domain        }};
struct adns__rrtype adns_r_ns      [1]= {{  5, rcf_cname         }};
struct adns__rrtype adns_r_soa     [1]= {{  5, rcf_soa           }};
struct adns__rrtype adns_r_soa_raw [1]= {{  6, rcf_soa_raw       }};
struct adns__rrtype adns_r_null    [1]= {{ 10, rcf_null          }};
struct adns__rrtype adns_r_ptr     [1]= {{ 12, rcf_ptr           }};
struct adns__rrtype adns_r_ptr_raw [1]= {{ 12, rcf_ptr_raw       }};
struct adns__rrtype adns_r_hinfo   [1]= {{ 13, rcf_hinfo         }};
struct adns__rrtype adns_r_mx      [1]= {{ 15, rcf_mx            }};
struct adns__rrtype adns_r_mx_raw  [1]= {{ 15, rcf_mx_raw        }};
struct adns__rrtype adns_r_txt     [1]= {{ 16, rcf_txt           }};
struct adns__rrtype adns_r_rp      [1]= {{ 17, rcf_rp_raw        }};
struct adns__rrtype adns_r_rp_raw  [1]= {{ 17, rcf_rp_raw        }};
