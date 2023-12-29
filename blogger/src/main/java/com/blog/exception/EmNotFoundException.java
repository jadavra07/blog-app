package com.blog.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class EmNotFoundException extends RuntimeException {

    public EmNotFoundException(String message) {
        super(message);
    }
}
