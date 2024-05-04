package com.demo.springsecurity.service.impl;

import jakarta.annotation.Resource;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 14:08
 * @Description:
 */
public class RegisterServiceImpl {


    public void register() {
        // 用户注册默认权限为user，在数据库中添加用户信息，权限为user

    }


}

//
//package com.demo.springsecurity.service.impl;
//
//import com.demo.springsecurity.mapper.StudentsMapper;
//import com.demo.springsecurity.mapper.RoleMapper;
//import com.demo.springsecurity.mapper.UserRoleMapper;
//import com.demo.springsecurity.pojo.Students;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.stereotype.Service;
//
//@Service
//public class RegisterServiceImpl {
//
//    @Autowired
//    private StudentsMapper studentsMapper;
//
//    @Autowired
//    private RoleMapper roleMapper;
//
//    @Autowired
//    private UserRoleMapper userRoleMapper;
//
//    public void register(Students student) {
//        // Add the new user to the database
//        studentsMapper.insert(student);
//
//        // Assign the default role to the new user
//        int roleId = roleMapper.getDefaultRoleId();
//        userRoleMapper.insert(student.getStudentID(), roleId);
//    }
//}