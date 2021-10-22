package com.spring.mvc.member.service;

import com.spring.mvc.member.domain.Member;
import com.spring.mvc.member.repository.MemberMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberMapper memberMapper;

    //회원가입 기능
    public void signUp(Member member) {

        //비밀번호 인코딩
        String rawPw = member.getPassword();
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodePw = encoder.encode(rawPw);
        member.setPassword(encodePw);

        memberMapper.register(member);
    }

    /**
     * 중복확인 기능
     * @param type - 검사 유형(account, email)
     * @param keyword - 검사값
     * @return 중복되면 true, 중복되지 않으면 false
     */
    public boolean isDuplicate(String type, String keyword) {
        Map<String, Object> checkMap = new HashMap<>();
        checkMap.put("type", type);
        checkMap.put("keyword", keyword);

        return memberMapper.isDuplicate(checkMap) == 1;
    }

    //회원정보 조회기능
    public Member getMember(String account) {
        return memberMapper.getUser(account);
    }

    //로그인 처리 기능
    public String login(String inputId, String inputPw) {

        Member member = memberMapper.getUser(inputId);
        if (member != null) {
            String dbPw = member.getPassword();
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

            return encoder.matches(inputPw, dbPw) ? "loginSuccess" : "pwFail";

        } else {
            return "idFail";
        }
    }
}