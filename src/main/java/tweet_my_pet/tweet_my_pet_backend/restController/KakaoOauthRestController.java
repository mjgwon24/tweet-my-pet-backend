package tweet_my_pet.tweet_my_pet_backend.restController;

import tweet_my_pet.tweet_my_pet_backend.service.KakaoService;  // KakaoService import
import tweet_my_pet.tweet_my_pet_backend.dto.KakaoUserInfo;     // KakaoUserInfo import

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.ui.Model;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth/kakao")
public class KakaoOauthRestController {

    private final KakaoService kakaoService;

    @Value("${kakao.client_id}")
    private String clientId;

    @Value("${kakao.redirect_uri}")
    private String redirectUri;

    // 1. 카카오 로그인 링크 반환
    @GetMapping("/login")
    public ResponseEntity<String> loginPage(Model model) {
        String location = "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id="
                + clientId + "&redirect_uri=" + redirectUri;
        return ResponseEntity.ok(location);
    }

    // 2. 카카오 콜백 처리
    @GetMapping("/callback")
    public ResponseEntity<?> callback(@RequestParam("code") String code) {
        String accessToken = kakaoService.getAccessToken(code);
        KakaoUserInfo userInfo = kakaoService.getUserInfo(accessToken);

        // 사용자 정보 확인 예시
        System.out.println("Kakao ID: " + userInfo.getId());
        System.out.println("Kakao Nickname: " + userInfo.getKakaoAccount().getProfile().getNickname());
        System.out.println("Kakao Email: " + userInfo.getKakaoAccount().getEmail());

        return ResponseEntity.ok("Login Success");
    }
}
