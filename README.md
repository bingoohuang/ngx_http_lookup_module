ngx_http_lookup_module
======================

lookup value in ranges 

this module is similar to map module. but it searchs in a list of ranges(long integer value pairs) to find a mapped value.

config example:

http {

    lookup $arg_scores $grade {
           ranges;
           default 0;
           100-1000 A;
           1001-2000 B;
           2001-3000 C;
    }
    
    lookup $arg_num $cityCode {
           ranges;
           default 00X000;
           18699100000-18699199999 089X890;
           18699200000-18699249999 089X892;
           18699300000-18699349999 089X893;
           18699400000-18699499999 089X891;
           18699500000-18699549999 089X894;
    }
    
    server {
          # ...
          location /city {
              echo $cityCode;
          }
    }
}

so to find city code we can:
curl --trace-time --trace trace.log http://127.0.0.1:8888/city?num=18699402100


PS: SOURCE was copied and changed from ngx_http_geo_module base on version 1.4.1.
