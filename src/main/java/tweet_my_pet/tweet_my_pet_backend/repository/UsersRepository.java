package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.userEmail = :email")
    Optional<User> findByUserEmail(@Param("email") String email);

    // userId가 가장 큰 값을 조회 (마지막 사용자의 ID)
    @Query("SELECT MAX(u.userId) FROM User u")
    Long findLastUserId();

    // userId로 사용자 조회
    @Query("SELECT u FROM User u WHERE u.userId = :userId")
    Optional<User> findByUserId(@Param("userId") Long userId);

    // 전화번호 중복 여부 확인
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.userPhoneNumber = :phoneNumber")
    boolean existsByPhoneNumber(@Param("phoneNumber") String phoneNumber);
}
