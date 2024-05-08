package com.demo.springsecurity.mapper;

import com.demo.springsecurity.pojo.SystemUser;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:22
 * @Description:
 */

@Mapper
public interface SystemUserMapper {

    @Update("update sys_user set username = 'lisi' where id = #{id}")
    void modifyStudentInfo(int id);

    @Select("select * from sys_user where username = #{username}")
    SystemUser findByUsername(String username);

    @Insert("insert into sys_user(username, password) values(#{username}, #{password})")
    void insertNewUser(String username, String password);
}
