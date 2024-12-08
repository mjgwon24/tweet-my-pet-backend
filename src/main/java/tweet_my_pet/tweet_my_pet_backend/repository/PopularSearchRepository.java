package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tweet_my_pet.tweet_my_pet_backend.entity.PopularSearch;

import java.util.Optional;
import java.util.List;

@Repository
public interface PopularSearchRepository extends JpaRepository<PopularSearch, Long> {
    Optional<PopularSearch> findBySearchTerm(String searchTerm);

    List<PopularSearch> findTop7ByOrderBySearchCountDesc();
}
