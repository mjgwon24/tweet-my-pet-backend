package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tweet_my_pet.tweet_my_pet_backend.entity.User;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;

public interface UsersRepository extends JpaRepository<NoApiUserLogin, Long> {
    // 아이디 중복 체크
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM NoApiUserLogin u WHERE u.loginId = :loginId")
    boolean existsByLoginId(String loginId);

    // 전화번호 중복 체크
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.userPhoneNumber = :phoneNumber")
    boolean existsByPhoneNumber(String phoneNumber);

    // 아이디로 사용자 조회
    NoApiUserLogin findByLoginId(String loginId);
}
