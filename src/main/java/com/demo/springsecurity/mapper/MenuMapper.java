package com.demo.springsecurity.mapper;

import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @Author: Yupeng Li
 * @Date: 4/5/2024 13:18
 * @Description:
 */

@Mapper
public interface MenuMapper {
    /**
     * 根据用户id查询用户权限
     * @param userId 用户id
     * @return 用户权限
     */
    List<String> selectPermsByUserId(Long userId);
}
