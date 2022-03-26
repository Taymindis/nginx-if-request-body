nginx-if-request-body
=====


For body filter before proxy to backend


Example:

```nginx
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
        proxy_pass http://localhost:7777;
        
    }

```