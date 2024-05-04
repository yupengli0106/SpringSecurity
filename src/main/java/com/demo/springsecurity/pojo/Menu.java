package com.demo.springsecurity.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 13:13
 * @Description:
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Menu {
    private String menu_name;
    private String path;
    private String component;
    private String visible;
    private String status;
    private String perms;
    private String icon;
    private String create_by;
    private String create_time;
    private String update_by;
    private String update_time;
    private String del_flag;
    private String remark;
}
