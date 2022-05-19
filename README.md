nginx-if-request-body
=====


For body filter before proxy to backend


Example:

```nginx
http {
  ....
    
    map "$uri" $forward_status {
        default 100; # 100 means nothing return, continue to proxy phase
        "~*.+?\.(css|js|bmp|gif|ico|jpeg|jpg|pict|png|svg|swf|tif)$" 418;
    }
   map "$request_body" $forward_status_by_body {
        default 100;
        "abc123xxx" 418;
        "~*.+?\.(css|js|bmp|gif|ico|jpeg|jpg|pict|png|svg|swf|tif)$" 418;
    }

  server {
   ...
        error_page 418 =200 /welcome_if_request_body;
        location /welcome_if_request_body {
            add_header Content-Type text/plain;
            return 200 "welcome_if_request_body, you hit it";
        }

        location = / {
            if_request_body on;
            return_status_if_body_eq "ASD" 418 on;
            return_status_if_body_eq "foo" 418;
            return_status_if_body_eq "john" 418;
            return_status_if_body_startswith "report" 418;
            return_status_if_body_contains "report" 418;
            return_status_if_body_regex "^[\d]+?abc" 418;
            return_status_if_variable_map_to $forward_status;
            return_status_if_variable_map_to $forward_status_by_body;
            proxy_pass http://localhost:7777;

        }
...
    }
}
```
