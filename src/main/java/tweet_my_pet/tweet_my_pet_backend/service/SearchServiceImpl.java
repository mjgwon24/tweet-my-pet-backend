package tweet_my_pet.tweet_my_pet_backend.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tweet_my_pet.tweet_my_pet_backend.dto.RecentSearchDto;
import tweet_my_pet.tweet_my_pet_backend.entity.PopularSearch;
import tweet_my_pet.tweet_my_pet_backend.entity.SearchHistory;
import tweet_my_pet.tweet_my_pet_backend.repository.PopularSearchRepository;
import tweet_my_pet.tweet_my_pet_backend.repository.SearchHistoryRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SearchServiceImpl implements SearchService {

    private final SearchHistoryRepository searchHistoryRepository;
    private final PopularSearchRepository popularSearchTermRepository;

    @Override
    @Transactional(readOnly = true)
    public List<RecentSearchDto> getRecentSearchTerms(Long userId) {
        return searchHistoryRepository.findTop7ByUserIdOrderBySearchedAtDesc(userId)
                .stream()
                .map(history -> new RecentSearchDto(history.getSearchTerm(), history.getSearchedAt()))
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> getPopularSearchTerms() {
        return popularSearchTermRepository.findTop7ByOrderBySearchCountDesc()
                .stream()
                .map(PopularSearch::getSearchTerm)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void saveSearchTerm(Long userId, String searchTerm) {
        // 중복된 검색어 확인
        SearchHistory existingSearch = searchHistoryRepository.findTop1ByUserIdAndSearchTermOrderBySearchedAtDesc(userId, searchTerm);

        if (existingSearch != null) {
            // 기존 검색어가 있으면 날짜 업데이트
            existingSearch.setSearchedAt(LocalDateTime.now());
            searchHistoryRepository.save(existingSearch);
        } else {
            // 새로운 검색어 저장
            SearchHistory searchHistory = new SearchHistory();
            searchHistory.setUserId(userId);
            searchHistory.setSearchTerm(searchTerm);
            searchHistoryRepository.save(searchHistory);

            // 최대 20개 제한
            List<SearchHistory> searchHistories = searchHistoryRepository.findByUserIdOrderBySearchedAtDesc(userId);
            if (searchHistories.size() > 20) {
                searchHistoryRepository.delete(searchHistories.get(searchHistories.size() - 1));
            }
        }

        // 인기 검색어 업데이트
        PopularSearch popularSearch = popularSearchTermRepository.findBySearchTerm(searchTerm)
                .orElse(new PopularSearch(searchTerm));
        popularSearch.setSearchCount(popularSearch.getSearchCount() + 1);
        popularSearchTermRepository.save(popularSearch);
    }

}
