package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UsersRepository extends JpaRepository<Users, Long> {
    // 아이디 중복 체크
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM Users u WHERE u.loginId = :loginId")
    boolean existsByLoginId(String loginId);

    // 전화번호 중복 체크
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM Users u WHERE u.phoneNumber = :phoneNumber")
    boolean existsByPhoneNumber(String phoneNumber);

    // 아이디로 사용자 조회
    Users findByLoginId(String loginId);
    Users findByKakaoId(String kakaoId);
}
