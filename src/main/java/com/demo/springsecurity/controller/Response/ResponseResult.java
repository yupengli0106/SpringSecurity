package com.demo.springsecurity.controller.Response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:26
 * @Description:
 */

@Data
@AllArgsConstructor
public class ResponseResult {
    private final Integer code;
    private final String message;
    private final Object data;

    public static ResponseResult success(Object data) {
        return new ResponseResult(200, "Success", data);
    }

    public static ResponseResult error(Integer code, String message) {
        return new ResponseResult(code, message, null);
    }

    public static ResponseResult error(ErrorEnum errorEnum) {
        return new ResponseResult(errorEnum.getCode(), errorEnum.getMessage(), null);
    }

    @Getter
    public enum ErrorEnum {
        // 定义错误码枚举
        INTERNAL_SERVER_ERROR(500, "Internal Server Error"),
        BAD_REQUEST(400, "Bad Request"),
        NOT_FOUND(404, "Not Found");

        private final Integer code;
        private final String message;

        ErrorEnum(Integer code, String message) {
            this.code = code;
            this.message = message;
        }

    }
}

