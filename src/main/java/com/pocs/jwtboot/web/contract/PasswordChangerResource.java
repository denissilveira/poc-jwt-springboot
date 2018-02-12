package com.pocs.jwtboot.web.contract;

public class PasswordChangerResource {
	
	private String oldPassword;
	private String newPassword;
	
	public PasswordChangerResource() {}

    public PasswordChangerResource(final String oldPassword, final String newPassword) {
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
    }

	public String getOldPassword() {
		return oldPassword;
	}
	public String getNewPassword() {
		return newPassword;
	}

}