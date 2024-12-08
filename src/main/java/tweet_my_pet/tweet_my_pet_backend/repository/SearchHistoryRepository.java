package tweet_my_pet.tweet_my_pet_backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tweet_my_pet.tweet_my_pet_backend.entity.SearchHistory;

import java.util.List;

@Repository
public interface SearchHistoryRepository extends JpaRepository<SearchHistory, Long> {
    List<SearchHistory> findTop7ByUserIdOrderBySearchedAtDesc(Long userId);
    SearchHistory findTop1ByUserIdAndSearchTermOrderBySearchedAtDesc(Long userId, String searchTerm);
    List<SearchHistory> findByUserIdOrderBySearchedAtDesc(Long userId);
}
