package com.pocs.jwtboot.model.enums;

import java.util.HashMap;
import java.util.Map;

public enum StatusEnum {
	
	OPEN,
	CLOSE,
	REJECT,
	IN_PROGRESS,
	DONE;

	private static final Map<String, StatusEnum> NAME_MAP = new HashMap<String, StatusEnum>();
	
	static {
    	for(StatusEnum value : values()){
    		NAME_MAP.put(value.name(), value);
    	}
    }
	
	public static StatusEnum getByName(String name){
        return NAME_MAP.get(name);
    }
}