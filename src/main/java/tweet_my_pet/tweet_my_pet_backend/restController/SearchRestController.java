package tweet_my_pet.tweet_my_pet_backend.restController;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tweet_my_pet.tweet_my_pet_backend.dto.RecentSearchDto;
import tweet_my_pet.tweet_my_pet_backend.service.SearchService;
import java.util.List;

@RestController
@RequestMapping("/api/search")
@RequiredArgsConstructor
public class SearchRestController {

    private static final Logger logger = LoggerFactory.getLogger(SearchRestController.class);

    private final SearchService searchService;

    @GetMapping("/recent")
    public ResponseEntity<List<RecentSearchDto>> getRecentSearchTerms(@RequestParam Long userId) {
        List<RecentSearchDto> recentSearchTerms = searchService.getRecentSearchTerms(userId);
        return ResponseEntity.ok(recentSearchTerms);
    }

    @GetMapping("/popular")
    public ResponseEntity<List<String>> getPopularSearchTerms() {
        List<String> popularSearchTerms = searchService.getPopularSearchTerms();
        return ResponseEntity.ok(popularSearchTerms);
    }

    @PostMapping
        public ResponseEntity<Void> saveSearchTerm(@RequestParam Long userId, @RequestParam String searchTerm) {
        searchService.saveSearchTerm(userId, searchTerm);
        logger.info("Search term saved: userId={}, searchTerm={}", userId, searchTerm);
        ResponseEntity<Void> response = ResponseEntity.status(201).build();
        logger.info("Response: {}", response);
        return ResponseEntity.status(201).build();
    }
}
