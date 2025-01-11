package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.userEmail = :email")
    User findByUserEmail(@Param("email") String email);

    @Query("SELECT MAX(u.userId) FROM User u")
    Long findLastUserId();

    @Query("SELECT u FROM User u WHERE u.userId = :userId")
    Optional<User> findByUserId(@Param("userId") Long userId);

    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE  u.userName = :userName and u.userPhoneNumber = :phoneNumber")
    boolean existsByUserPhoneNumberAndUserName(@Param("phoneNumber") String phoneNumber, @Param("userName") String userName);

    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.userPhoneNumber = :phoneNumber")
    boolean existsByPhoneNumber(@Param("phoneNumber") String phoneNumber);

    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE  u.userName = :userName and u.userPhoneNumber = :phoneNumber and u.userEmail = :userEmail")
    boolean existsByUserPhoneNumberAndUserNameAndUserEmail(String phoneNumber, String userName, String userEmail);
}
