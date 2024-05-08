package com.demo.springsecurity.pojo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;


/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:21
 * @Description:
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "sys_user")
public class SystemUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "nick_name")
    private String nickname;

    private String password;
    private String status;
    private String email;

    @Column(name = "phone_number")
    private String phoneNumber;

    private String sex;
    private String avatar;

    @Column(name = "user_type", nullable = false)
    private String userType;

    @Column(name = "create_by")
    private Long createBy;

    @Column(name = "create_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date createTime;

    @Column(name = "update_by")
    private Long updateBy;

    @Column(name = "update_time")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updateTime;

    @Column(name = "del_flag", nullable = false)
    private Integer delFlag;
}
