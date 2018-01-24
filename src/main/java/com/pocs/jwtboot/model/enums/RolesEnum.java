package com.pocs.jwtboot.model.enums;

import java.util.HashMap;
import java.util.Map;

public enum RolesEnum {
	
	ADMIN("ADMIN", "ROLE_ADMIN"), 
	USER("USER", "ROLE_USER"), 
	STARTUP("STARTUP", "ROLE_STARTUP"), 
	PARTNER("PARTNER", "ROLE_PARTNER");

	private final String code;
	private final String role;
	private static final Map<String, RolesEnum> CODE_MAP = new HashMap<String, RolesEnum>();
	
	static {
    	for(RolesEnum value : values()){
    		CODE_MAP.put(value.code, value);
    	}
    }
	
	public static RolesEnum getByCode(String code){
        return CODE_MAP.get(code);
    }

	private RolesEnum(final String code, final String role) {
		this.code = code;
		this.role = role;
	}

	public String getRole() {
		return role;
	}
	public String getCode() {
		return code;
	}

}