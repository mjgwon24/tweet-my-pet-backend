package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "company_introduce_video")
public class CompanyIntroduceVideo {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "company_introduce_video_id", nullable = false)
    private Long companyIntroduceVideoId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "company_introduce_id", nullable = false)
    private CompanyIntroduce companyIntroduce;

    @Column(name = "company_introduce_video_content", nullable = false)
    private String companyIntroduceVideoContent;

}