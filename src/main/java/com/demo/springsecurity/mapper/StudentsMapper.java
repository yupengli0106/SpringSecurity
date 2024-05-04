package com.demo.springsecurity.mapper;

import com.demo.springsecurity.pojo.Students;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

/**
 * @Author: Yupeng Li
 * @Date: 17/4/2024 16:22
 * @Description:
 */

@Mapper
public interface StudentsMapper {

    @Update("update students set name = 'lisi' where studentId = #{id}")
    void modifyStudentInfo(int id);

    @Select("select * from students where username = #{username}")
    Students findByUsername(String username);
}
