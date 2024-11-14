package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import tweet_my_pet.tweet_my_pet_backend.entity.CompanyIntroducePicture;

public interface CompanyIntroducePictureRepository extends JpaRepository<CompanyIntroducePicture, Long> {

}
