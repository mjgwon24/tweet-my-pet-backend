package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tweet_my_pet.tweet_my_pet_backend.entity.NaverApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

import java.util.Optional;

public interface NaverApiUserLoginRepository extends JpaRepository<NaverApiUserLogin, Long> {
    NaverApiUserLogin findByNaverApiUserName(String name); // 네이버 ID로 로그인 정보 검색

    NaverApiUserLogin findByUser(User user); // User 객체로 로그인 정보 검색
}
