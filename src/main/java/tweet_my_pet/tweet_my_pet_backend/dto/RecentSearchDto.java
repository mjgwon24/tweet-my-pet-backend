package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 최근 검색어 DTO
 * @since 2024.11.17
 */
@Data
@AllArgsConstructor
public class RecentSearchDto {
    private String searchTerm;
    private LocalDateTime searchedAt;
}
