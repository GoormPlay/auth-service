package com.goormplay.authservice.auth.service;

import com.goormplay.authservice.auth.dto.Member.MemberDto;
import com.goormplay.authservice.auth.dto.SignInRequestDto;
import com.goormplay.authservice.auth.dto.SignInResponseDto;
import com.goormplay.authservice.auth.dto.SignUpRequestDto;


public interface AuthService {

    SignInResponseDto signIn(SignInRequestDto dto);

    void signUp(SignUpRequestDto dto);
    void deleteTransaction(String username);
    String createJwt(MemberDto memberDto);
    String tokenRefresh();
    void logout();
    void createTestAccount(SignUpRequestDto dto);
}
