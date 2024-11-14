package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tweet_my_pet.tweet_my_pet_backend.entity.CompanyIntroduceVideo;

public interface CompanyIntroduceVideoRepository extends JpaRepository<CompanyIntroduceVideo, Long> {

}
