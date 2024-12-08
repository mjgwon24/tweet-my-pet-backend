package tweet_my_pet.tweet_my_pet_backend.service;

import tweet_my_pet.tweet_my_pet_backend.dto.RecentSearchDto;

import java.util.List;

public interface SearchService {
    List<RecentSearchDto> getRecentSearchTerms(Long userId);
    List<String> getPopularSearchTerms();
    void saveSearchTerm(Long userId, String searchTerm);
}
