package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;

public interface NoApiUserLoginRepository extends JpaRepository<NoApiUserLogin, Long> {
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM NoApiUserLogin u WHERE u.LoginId = :loginId")
    boolean existsByLoginId(String LoginId);

    // 아이디로 사용자 조회
    NoApiUserLogin findByLoginId(String LoginId);
}
