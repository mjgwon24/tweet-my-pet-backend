package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "search_history", schema = "tweet_my_pet")
public class SearchHistory {
    @Id
    @Column(name = "search_history_id", nullable = false)
    private Long searchHistoryId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "search_history_content", nullable = false)
    private String searchHistoryContent;

    @Column(name = "search_history_date", nullable = false)
    private Instant searchHistoryDate;

}