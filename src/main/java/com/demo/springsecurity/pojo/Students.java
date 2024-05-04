package com.demo.springsecurity.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:21
 * @Description:
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Students {
    private Integer StudentID;
    private String Name;
    private Integer Age;
    private String Major;
    private String username;
    private String password;
}
