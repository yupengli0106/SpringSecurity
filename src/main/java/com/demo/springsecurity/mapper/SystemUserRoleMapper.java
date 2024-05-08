package com.demo.springsecurity.mapper;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;

/**
 * @Author: Yupeng Li
 * @Date: 8/5/2024 16:05
 * @Description:
 */
@Mapper
public interface SystemUserRoleMapper {

    /**
     * Set the default role for the new user
     * @param userID the ID of the new user
     * @Description: The default role is the role with ID 1, means the user can only query the data.
     */
    @Insert("insert into sys_user_role(user_id, role_id) values(#{userID}, 1)")
    void setDefaultRole(Long userID);
}
