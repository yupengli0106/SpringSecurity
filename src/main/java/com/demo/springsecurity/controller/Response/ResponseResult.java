package com.demo.springsecurity.controller.Response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:26
 * @Description:
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResponseResult {
    Integer code;
    String message;
    Object data;
}
