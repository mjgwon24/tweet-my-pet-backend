package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tweet_my_pet.tweet_my_pet_backend.entity.store.StoreFeature;

@Repository
public interface StoreFeatureRepository extends JpaRepository<StoreFeature, Long> {
}
