package com.saltyfish.admin.domain.enums;

import com.saltyfish.framework.tools.response.IResultCode;
import lombok.AllArgsConstructor;

/**
 * @author: 番薯(Amos)
 * @dateTime: 10:15/09:03:2023
 * @version: v1.0
 * @description:
 */
@AllArgsConstructor
public enum ErrorCodeEnum implements IResultCode {
    
    DATA_NOT_EXISTS(1004001000, "数据不存在"),
    
    ;
    
    private Integer code;
    private String message;
    
    @Override
    public Integer getCode() {
        return code;
    }
    
    public void setCode(final Integer code) {
        this.code = code;
    }
    
    @Override
    public String getMessage() {
        return this.message;
    }
    
    public void setMessage(final String message) {
        this.message = message;
    }
}
