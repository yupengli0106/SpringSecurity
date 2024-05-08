package com.demo.springsecurity.pojo;

import jakarta.persistence.Column;
import jakarta.persistence.Table;

/**
 * @Author: Yupeng Li
 * @Date: 8/5/2024 15:54
 * @Description: 这是一个系统用户角色实体类，用于描述系统用户的角色信息。
 * 比如：userID  roleID
 *          1       1（查询,删除）
 *          2       2（查询）
 *
 *说明：userID为用户ID，roleID为角色ID，这两个字段是外键，分别关联了sys_user表和sys_role_menu表。
 *              roleID为1: 查询,删除
 *              roleID为2: 查询
 *
 *  这里的roleID为1和2是在sys_role_menu表中定义的，分别对应了查询和删除的权限。
 */

@Table(name = "sys_user_role")
public class SystemUserRole {
    @Column(name = "user_id", nullable = false)
    private Integer userID;

    @Column(name = "role_id", nullable = false)
    private Integer roleID;
}
