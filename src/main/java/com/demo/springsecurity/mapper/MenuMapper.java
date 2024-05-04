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
    List<String> selectPermsByUserId(Long userId);
}
