package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.entity.NoApiUserLogin;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

public interface NoApiUserLoginRepository extends JpaRepository<NoApiUserLogin, Long> {
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM NoApiUserLogin u WHERE u.loginId = :loginId")
    boolean existsByLoginId(@Param("loginId") String loginId);

    // 전화번호로 로그인ID조회
    @Query("SELECT n.loginId FROM NoApiUserLogin n JOIN n.user u WHERE u.userPhoneNumber = :phoneNumber")
    String findLoginIdByPhoneNumber(@Param("phoneNumber") String phoneNumber);

    // 유저 비밀번호 변경
    @Modifying
    @Transactional
    @Query("UPDATE NoApiUserLogin n SET n.password = :password WHERE n.user.userId = (SELECT u.userId FROM User u WHERE u.userPhoneNumber = :phoneNumber)")
    int updateNoApiLoginUserPasswordByPhoneNumber(@Param("phoneNumber") String phoneNumber, @Param("password") String password);

    // 아이디로 사용자 조회
    NoApiUserLogin findByLoginId(String LoginId);
}
