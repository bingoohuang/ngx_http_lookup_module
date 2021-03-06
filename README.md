ngx_http_lookup_module
======================

lookup value in ranges

this module is similar to ngx_http_geo_module. but it searchs in a list of ranges(long value pairs) to find a mapped value.

config example:

```nginx
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

    lookup $mobile $city {
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
          location /cityCode {
            echo $cityCode;
          }

          location /city {
            set $mobile 100;
            content_by_lua '
                ngx.header.content_type = "text/plain"
                local request_method = ngx.var.request_method

                local args = nil
                if "GET" == request_method then
                    args = ngx.req.get_uri_args()
                elseif "POST" == request_method then
                    ngx.req.read_body()
                    args = ngx.req.get_post_args()
                end

                ngx.var.mobile = args.mobile
                ngx.say(ngx.var.city)
            ';
          }
    }
}
```

# install
`./configure --prefix=/path/to/nginx --add-module=/path/to/github/ngx_http_lookup_module/`

# install on MAC
`./configure --prefix=/Users/bingoo/run/openresty/ --with-openssl=/usr/local/Cellar/openssl/1.0.2l --with-cc-opt="-I/usr/local/Cellar/openssl/1.0.2l/include -I/usr/local/Cellar/pcre/8.41/include" --with-ld-opt="-L/usr/local/Cellar/openssl/1.0.2l/lib -L/usr/local/Cellar/pcre/8.40/lib" --add-module=/Users/bingoo/GitHub/ngx_http_lookup_module`

# demo
so to find city code we can:
```
> curl -w "%{time_total}" "http://127.0.0.1:8077/cityCode?num=18699402100"
089X891
0.006483
> curl --data "mobile=18699199988" "http://127.0.0.1:8077/city"
089X890

> curl --data "mobile=18699549999" "http://127.0.0.1:8077/city"
089X894

> curl "http://127.0.0.1:8077/city?mobile=18699199988"
089X890

> curl "http://127.0.0.1:8077/city?mobile=18699549999"
089X894

> curl "http://127.0.0.1:8077/city?mobile=18551855099"
00X000
```

PS: SOURCE was copied and changed from ngx_http_geo_module base on version 1.4.1.
