package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tweet_my_pet.tweet_my_pet_backend.entity.KakaoApiUserLogin;

public interface KakaoApiUserLoginRepository extends JpaRepository<KakaoApiUserLogin, Long> {

    KakaoApiUserLogin findByKakaoApiUserId(Long kakaoApiUserId);

}
