package tweet_my_pet.tweet_my_pet_backend.service;

import jakarta.transaction.Transactional;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import tweet_my_pet.tweet_my_pet_backend.entity.NaverApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.repository.NaverApiUserLoginRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.UsersRepository;
import java.util.Map;
import java.util.Optional;

@Transactional
@Service
public class NaverService {

    public Map<String, Object> getUserInfoFromNaver(String accessToken) {
        String userInfoUrl = "https://openapi.naver.com/v1/nid/me";
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> request = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(userInfoUrl, HttpMethod.GET, request, Map.class);

        if (response.getStatusCode() == HttpStatus.OK) {
            return response.getBody();
        } else {
            throw new RuntimeException("사용자 정보 요청 실패: " + response.getStatusCode());
        }
    }

    private final UsersRepository usersRepository;
    private final NaverApiUserLoginRepository naverApiUserLoginRepository;

    public NaverService(UsersRepository usersRepository, NaverApiUserLoginRepository naverApiUserLoginRepository) {
        this.usersRepository = usersRepository;
        this.naverApiUserLoginRepository = naverApiUserLoginRepository;
    }

    public User registerOrLoginUser(String email, String name, String mobile, String accessToken, String refreshToken) {
        // 1. 사용자 이메일로 기존 사용자 검색
        User user = usersRepository.findByUserEmail(email);

        if (user == null) {
            // 2. 기존 사용자가 없으면 새로운 사용자 생성
            user = User.builder()
                    .userName(name)
                    .userEmail(email)
                    .userPhoneNumber(mobile)
                    .build();
            usersRepository.save(user); // 새로운 사용자 저장
        }

        // 3. 네이버 로그인 정보 처리
        NaverApiUserLogin naverApiUserLogin = naverApiUserLoginRepository.findByUser(user);

        if (naverApiUserLogin == null) {
            // 3-1. 기존 네이버 로그인 정보가 없으면 새로 생성
            naverApiUserLogin = NaverApiUserLogin.builder()
                    .user(user) // User와 연관
                    .naverApiUserName(user.getUserName()) // User의 userName 저장
                    .naverApiAccessToken(accessToken)
                    .naverApiRefreshToken(refreshToken)
                    .build();
            naverApiUserLoginRepository.save(naverApiUserLogin);
        } else {
            // 3-2. 기존 네이버 로그인 정보가 있으면 업데이트
            naverApiUserLogin.setNaverApiAccessToken(accessToken);
            naverApiUserLogin.setNaverApiRefreshToken(refreshToken);
            naverApiUserLogin.setNaverApiUserName(user.getUserName()); // userName 업데이트
            naverApiUserLoginRepository.save(naverApiUserLogin);
        }

        return user; // 최종 저장된 User 반환
    }
}