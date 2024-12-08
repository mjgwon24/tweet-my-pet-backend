package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 인기 검색어 엔터티
 * @since 2024.11.17
 */

@Entity
@Table(name = "popular_search_terms")
@Getter
@Setter
@NoArgsConstructor
public class PopularSearch {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "search_term", nullable = false, unique = true, length = 255)
    private String searchTerm;

    @Column(name = "search_count", nullable = false)
    private Long searchCount = 0L;

    public PopularSearch(String searchTerm) {
        this.searchTerm = searchTerm;
    }
}
