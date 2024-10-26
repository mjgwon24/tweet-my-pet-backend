package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tweet_my_pet.tweet_my_pet_backend.entity.Users;

public interface UsersRepository extends JpaRepository<Users, Long> {
}
